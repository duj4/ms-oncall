package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/target/goalert/auth"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/permission"
)

// CollectUpdate reuses the frozen relationship projections and planner input.
// removed is a SERVER computed diff, not a wire selector. The owning mutation
// must stabilize its before-state before calling with Recheck. No root is
// enqueued for removal: an update never borrows DeleteResources semantics.
func CollectUpdate(ctx context.Context, tx *sql.Tx, root ds.Resource, removed []ds.Resource, purpose Purpose, authorize AuthorizeFacts) (Result, error) {
	bad := Result{Collection: ds.Collection{Completeness: ds.DependenciesIncomplete}}
	if ctx == nil || tx == nil || authorize == nil || len(removed) == 0 || len(removed) > ds.DefaultBudget().MaxTargets || purpose < Preview || purpose > Recheck {
		return bad, unavailable()
	}
	c := collector{ctx: ctx, tx: tx, limits: DefaultLimits(), removed: map[ds.Resource]bool{}, checked: map[ds.Resource]bool{}, queue: map[ds.ResourceKind][]string{}}
	var org, parent string
	query := identityQueries[root.Kind]
	if root.Kind == ds.ResourceEscalationPolicyStep {
		query = `SELECT p.organization_id::text FROM public.escalation_policy_steps s JOIN public.escalation_policies p ON p.id=s.escalation_policy_id WHERE s.id=$1`
		if err := tx.QueryRowContext(ctx, `SELECT escalation_policy_id::text FROM public.escalation_policy_steps WHERE id=$1`, root.ID).Scan(&parent); err != nil {
			return bad, safeError(err)
		}
	} else if root.Kind != ds.ResourceEscalationPolicy && root.Kind != ds.ResourceSchedule {
		return bad, unavailable()
	}
	if err := tx.QueryRowContext(ctx, query, root.ID).Scan(&org); err != nil {
		return bad, safeError(err)
	}
	organizationID, err := uuid.Parse(org)
	if err != nil || organizationID == uuid.Nil {
		return bad, unavailable()
	}
	facts := Target{resource: root, organization: organizationID}
	if parent != "" {
		facts.owner = ds.Resource{Kind: ds.ResourceEscalationPolicy, ID: parent}
	}
	if err := authorize(ctx, tx, facts); err != nil {
		return bad, unavailable()
	}
	c.organization = org
	var readOnly, isolation string
	if err := tx.QueryRowContext(ctx, `SELECT current_setting('transaction_read_only'),current_setting('transaction_isolation'),statement_timestamp()`).Scan(&readOnly, &isolation, &c.result.ObservedAt); err != nil {
		return bad, safeError(err)
	}
	if purpose == Preview && (readOnly != "on" || isolation != "repeatable read") || purpose == Recheck && (readOnly != "off" || isolation != "read committed") {
		return bad, unavailable()
	}
	fingerprint, err := updateScope(ctx, tx, org, purpose == Recheck)
	if err != nil {
		return bad, err
	}
	c.global = permission.System(ctx)
	for _, r := range removed {
		var p projection
		switch {
		case root.Kind == ds.ResourceEscalationPolicy && r.Kind == ds.ResourceEscalationPolicyStep:
			p = edge(ds.RelationshipStepRouting, r.Kind, root.Kind, `public.escalation_policy_steps s JOIN public.escalation_policies p ON p.id=s.escalation_policy_id`, "s.id", "s.id", "p.id", "p.organization_id")
		case root.Kind == ds.ResourceEscalationPolicyStep && r.Kind == ds.ResourceEscalationPolicyAction:
			p = owned(edge(ds.RelationshipRemovedAction, r.Kind, root.Kind, actionFrom, "a.id", "a.id", "st.id", "ep.organization_id"), ds.ResourceEscalationPolicy, ds.ResourceEscalationPolicy, "ep.id", "ep.id")
		case root.Kind == ds.ResourceSchedule && r.Kind == ds.ResourceScheduleRule:
			p = edge(ds.RelationshipRemovedRule, r.Kind, root.Kind, ruleFrom, "r.id", "r.id", "s.id", "s.organization_id")
		default:
			return bad, unavailable()
		}
		before := len(c.result.Collection.Dependencies)
		if err := c.read(p, []string{r.ID}, false); err != nil {
			return bad, safeError(err)
		}
		if len(c.result.Collection.Dependencies) != before+1 || c.result.Collection.Dependencies[before].Referencing != root {
			return bad, unavailable()
		}
		c.enqueue(r)
	}
	for len(c.queue) != 0 {
		kinds := make([]ds.ResourceKind, 0, len(c.queue))
		for k := range c.queue {
			kinds = append(kinds, k)
		}
		slices.Sort(kinds)
		kind := kinds[0]
		ids := c.queue[kind]
		delete(c.queue, kind)
		slices.Sort(ids)
		if err := c.collectKind(kind, ids); err != nil {
			return bad, safeError(err)
		}
		for _, id := range ids {
			c.checked[ds.Resource{Kind: kind, ID: id}] = true
		}
	}
	if err := c.validateReferences(); err != nil {
		return bad, safeError(err)
	}
	for r := range c.checked {
		c.result.Collection.Checked = append(c.result.Collection.Checked, r)
	}
	c.result.Collection.Completeness = ds.DependenciesComplete
	refs, err := c.updateReferenceState()
	if err != nil {
		return bad, err
	}
	c.result.ScopeFingerprint = updateDigest(fingerprint + ":" + refs)
	c.result.Limits = c.limits
	return c.result, nil
}

// Re-observe admission in the actual snapshot, independently of wire input.
// PlatformAdmin's existing global update scope retains its real Home attribution.
// Row SHARE locks on recheck keep actor and organization changes outside commit.
func updateScope(ctx context.Context, tx *sql.Tx, target string, lock bool) (string, error) {
	if lock {
		if err := updateLock(ctx, tx, `SELECT id::text FROM public.organizations WHERE id=$1 FOR SHARE NOWAIT`, target); err != nil {
			return "", err
		}
		if err := updateLock(ctx, tx, `SELECT organization_id::text FROM public.normal_organizations WHERE organization_id=$1 FOR SHARE NOWAIT`, target); err != nil {
			return "", err
		}
	}
	var normalTarget bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM public.organizations o JOIN public.normal_organizations n ON n.organization_id=o.id AND n.organization_classification=o.classification WHERE o.id=$1 AND o.classification='NORMAL')`, target).Scan(&normalTarget); err != nil || !normalTarget {
		return "", unavailable()
	}

	if permission.System(ctx) {
		if permission.UserID(ctx) != "" || permission.Service(ctx) || permission.Source(ctx) != nil || auth.RequesterFromContext(ctx) != nil || executioncontext.ExecutionContextFromContext(ctx) != nil {
			return "", unavailable()
		}
		return updateDigest("system:" + permission.SystemComponentName(ctx) + ":" + target), nil
	}
	ec, err := executioncontext.CheckHumanAuthority(ctx)
	if err != nil {
		return "", unavailable()
	}
	home, ok := ec.HomeOrganizationID()
	if !ok || (!ec.Privileges().PlatformAdmin() && home.String() != target) {
		return "", unavailable()
	}
	if lock {
		for _, q := range []string{
			`SELECT id::text FROM public.users WHERE id=$1 FOR SHARE NOWAIT`,
			`SELECT user_id::text FROM public.user_organization_assignments WHERE user_id=$1 FOR SHARE NOWAIT`,
		} {
			if err := updateLock(ctx, tx, q, permission.UserID(ctx)); err != nil {
				return "", err
			}
		}
		if err := updateLock(ctx, tx, `SELECT id::text FROM public.organizations WHERE id=ANY($1::uuid[]) ORDER BY id FOR SHARE NOWAIT`, pq.Array([]string{home.String(), target})); err != nil {
			return "", err
		}
		if err := updateLock(ctx, tx, `SELECT organization_id::text FROM public.normal_organizations WHERE organization_id=ANY($1::uuid[]) ORDER BY organization_id FOR SHARE NOWAIT`, pq.Array([]string{home.String(), target})); err != nil {
			return "", err
		}
	}
	var org, role, organizationRole string
	if err := tx.QueryRowContext(ctx, userOrganizations+` SELECT organization_id::text,user_role::text,organization_role::text FROM user_org WHERE user_id=$1`, permission.UserID(ctx)).Scan(&org, &role, &organizationRole); err != nil {
		return "", unavailable()
	}
	expectedRole := "user"
	if permission.Admin(ctx) {
		expectedRole = "admin"
	}
	if org != home.String() || role != expectedRole || organizationRole != string(ec.Privileges().OrganizationRole()) {
		return "", unavailable()
	}
	var normal bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM public.organizations o JOIN public.normal_organizations n ON n.organization_id=o.id AND n.organization_classification=o.classification WHERE o.id=$1 AND o.classification='NORMAL')`, target).Scan(&normal); err != nil || !normal {
		return "", unavailable()
	}
	return updateDigest(fmt.Sprint(ec.PrincipalKind(), ":", ec.ActualActorID(), ":", ec.AuthorityMode(), ":", org, ":", role, ":", organizationRole, ":", target)), nil
}

func updateLock(ctx context.Context, tx *sql.Tx, query string, args ...any) error {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return safeError(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return unavailable()
		}
		n++
		if n > DefaultLimits().MaxRows {
			return limitExceeded()
		}
	}
	return safeUpdateRowsError(rows.Err())
}

func safeUpdateRowsError(err error) error {
	if err == nil {
		return nil
	}
	return safeError(err)
}

func updateDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// UpdateScope corroborates the current actor and actual persisted target scope.
// Operation admission remains with the existing Update resolver.
func UpdateScope(ctx context.Context, tx *sql.Tx, target uuid.UUID, locked bool) (string, error) {
	return updateScope(ctx, tx, target.String(), locked)
}

// Safe state of retained business targets participates in invalidation. Only
// narrow identity/configuration projections are read; provider payloads and
// personal destinations never enter the manifest.
func (c *collector) updateReferenceState() (string, error) {
	groups := map[ds.ResourceKind][]string{}
	for _, d := range c.result.Collection.Dependencies {
		for _, r := range append([]ds.Resource{d.Target, d.Referencing}, d.Before.References...) {
			if r.Kind == ds.ResourceUser || r.Kind == ds.ResourceSchedule || r.Kind == ds.ResourceRotation {
				if !slices.Contains(groups[r.Kind], r.ID) {
					groups[r.Kind] = append(groups[r.Kind], r.ID)
				}
			}
		}
	}
	state := ""
	for _, kind := range []ds.ResourceKind{ds.ResourceUser, ds.ResourceSchedule, ds.ResourceRotation} {
		ids := groups[kind]
		if len(ids) == 0 {
			continue
		}
		slices.Sort(ids)
		query := ""
		switch kind {
		case ds.ResourceUser:
			query = userOrganizations + ` SELECT COALESCE(jsonb_agg(jsonb_build_array(user_id,organization_id,user_role,organization_role) ORDER BY user_id),'[]'::jsonb)::text FROM user_org WHERE user_id=ANY($1::uuid[])`
		case ds.ResourceSchedule:
			query = `SELECT COALESCE(jsonb_agg(jsonb_build_array(id,organization_id,time_zone) ORDER BY id),'[]'::jsonb)::text FROM public.schedules WHERE id=ANY($1::uuid[])`
		case ds.ResourceRotation:
			query = `SELECT COALESCE(jsonb_agg(jsonb_build_array(id,organization_id,time_zone,type) ORDER BY id),'[]'::jsonb)::text FROM public.rotations WHERE id=ANY($1::uuid[])`
		}
		var raw string
		if err := c.queryRow(query, pq.Array(ids)).Scan(&raw); err != nil {
			return "", safeError(err)
		}
		state += fmt.Sprint(kind, ":", raw, ":")
	}
	return updateDigest(state), nil
}
