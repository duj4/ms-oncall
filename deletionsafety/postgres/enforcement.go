package postgres

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	ds "github.com/target/goalert/deletionsafety"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation/validate"
)

// Selector preserves the legacy DeleteAll selection. IntegrationKey uses its
// legacy credential selector ONLY as a SQL predicate, never as a plan identity.
// Do not log or serialize selectors.
type Selector = guard.Selector

// Enforce joins the existing READ COMMITTED transaction. It never begins,
// commits, rolls back, writes audit, or expands the explicit selection. The
// authorizer is trusted server code, identical to Preview's operation admission.
// A guard is issued only after complete fresh facts and the accepted BuildPlan.
func Enforce(ctx context.Context, tx *sql.Tx, raw []Selector, expected string, acknowledged bool, authorize AuthorizeFacts) (context.Context, error) {
	if ctx == nil || tx == nil || authorize == nil {
		return ctx, unavailable()
	}
	if len(raw) == 0 {
		return ctx, nil
	}
	// Validate RAW counts and UUIDs before normalization/deduplication.
	groups := map[ds.ResourceKind][]string{}
	for _, s := range raw {
		if _, ok := identityQueries[s.Kind]; !ok {
			return ctx, unavailable()
		}
		groups[s.Kind] = append(groups[s.Kind], s.ID)
	}
	for _, kind := range []ds.ResourceKind{ds.ResourceRotation, ds.ResourceUserOverride, ds.ResourceSchedule, ds.ResourceUser, ds.ResourceIntegrationKey, ds.ResourceService, ds.ResourceEscalationPolicy, ds.ResourceNotificationRule, ds.ResourceContactMethod} {
		ids := groups[kind]
		if len(ids) == 0 {
			continue
		}
		limit := 50
		if kind == ds.ResourceUser {
			limit = 100
		}
		if _, err := validate.ParseManyUUID(map[ds.ResourceKind]string{ds.ResourceService: "ServiceID", ds.ResourceEscalationPolicy: "EscalationPolicyID", ds.ResourceSchedule: "ScheduleID", ds.ResourceRotation: "RotationID", ds.ResourceUser: "UserID", ds.ResourceContactMethod: "ContactMethodID", ds.ResourceNotificationRule: "NotificationRuleID", ds.ResourceIntegrationKey: "IntegrationKeyID", ds.ResourceUserOverride: "UserOverrideID"}[kind], ids, limit); err != nil {
			return ctx, err
		}
	}
	if len(raw) > ds.DefaultBudget().MaxTargets {
		return ctx, limitExceeded()
	}
	var isolation, readOnly string
	if err := tx.QueryRowContext(ctx, `SELECT current_setting('transaction_isolation'),current_setting('transaction_read_only')`).Scan(&isolation, &readOnly); err != nil {
		return ctx, safeError(err)
	}
	if isolation != "read committed" || readOnly != "off" {
		return ctx, unavailable()
	}
	var err error
	ctx, err = guard.Fence(ctx, tx)
	if err != nil {
		return ctx, err
	}
	// Bound the WHOLE batch; its fences survive cancellation until owner release.
	collectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var targets []ds.Resource
	seen := map[ds.Resource]bool{}
	for _, s := range raw {
		s.ID = uuid.MustParse(s.ID).String()
		root := ds.Resource{Kind: s.Kind, ID: s.ID}
		if root.Kind == ds.ResourceIntegrationKey {
			if err := tx.QueryRowContext(collectCtx, `SELECT audit_resource_id::text FROM public.integration_keys WHERE id=$1::uuid`, s.ID).Scan(&root.ID); err != nil {
				if errors.Is(err, sql.ErrNoRows) && permission.System(ctx) {
					continue
				}
				return ctx, unavailable()
			}
			if root.ID == s.ID {
				return ctx, unavailable()
			}
		}
		var exists bool
		// Identity existence is distinct from scope resolution (broken scope fails closed).
		table, key := enforcementIdentity(root.Kind)
		if err := tx.QueryRowContext(collectCtx, `SELECT EXISTS(SELECT FROM public.`+table+` WHERE `+key+`=$1::uuid)`, root.ID).Scan(&exists); err != nil {
			return ctx, safeError(err)
		}
		if !exists {
			if permission.System(ctx) || root.Kind == ds.ResourceContactMethod || root.Kind == ds.ResourceNotificationRule {
				continue
			}
			return ctx, sql.ErrNoRows
		}

		if !seen[root] {
			targets = append(targets, root)
			seen[root] = true
		}
	}
	slices.SortFunc(targets, func(a, b ds.Resource) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return strings.Compare(a.ID, b.ID)
	})
	collection := ds.Collection{Completeness: ds.DependenciesComplete}
	remaining := ds.DefaultBudget().MaxDependencies
	var fingerprint string
	for _, root := range targets {
		limits := DefaultLimits()
		limits.MaxRows = max(1, remaining)
		result, err := Collect(collectCtx, tx, root, Recheck, limits, authorize)
		if err != nil {
			return ctx, safeError(err)
		}
		if result.Collection.Completeness != ds.DependenciesComplete || !slices.Contains(result.Collection.Checked, root) || fingerprint != "" && fingerprint != result.ScopeFingerprint {
			return ctx, unavailable()
		}
		fingerprint = result.ScopeFingerprint
		collection.Checked = append(collection.Checked, result.Collection.Checked...)
		collection.Dependencies = append(collection.Dependencies, result.Collection.Dependencies...)
		for _, d := range result.Collection.Dependencies {
			remaining -= 1 + len(d.Before.References) + len(d.After.References)
		}
		if remaining < 0 {
			return ctx, limitExceeded()
		}
	}
	if len(targets) == 0 && expected != "" {
		return ctx, &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
	}
	var plan ds.DeletionPlan
	if len(targets) > 0 {
		intent := make([]ds.DestructiveChange, len(targets))
		for i, r := range targets {
			intent[i] = ds.DestructiveChange{Resource: r, Kind: ds.ChangeDeleted}
		}
		var err error
		plan, err = ds.BuildPlan(ds.PlanInput{Operation: ds.OperationDeleteResources, Targets: targets, Intent: intent, Collection: collection, ScopeFingerprint: fingerprint}, ds.Budget{})
		if err != nil {
			return ctx, safeError(err)
		}
		// A confirmed BLOCK is still BLOCK. User's uncoordinated JSON writers must
		// remain unavailable even for a currently empty/ended reference graph.
		if !plan.CanProceed() {
			return ctx, plan.Check(expected, acknowledged)
		}
		if len(groups[ds.ResourceUser]) > 0 {
			return ctx, unavailable()
		}
		if err := plan.Check(expected, acknowledged); err != nil {
			return ctx, err
		}
	}
	return guard.Bind(ctx, tx, raw, plan, expected, acknowledged)
}

func enforcementIdentity(kind ds.ResourceKind) (string, string) {
	switch kind {
	case ds.ResourceService:
		return "services", "id"
	case ds.ResourceEscalationPolicy:
		return "escalation_policies", "id"
	case ds.ResourceSchedule:
		return "schedules", "id"
	case ds.ResourceRotation:
		return "rotations", "id"
	case ds.ResourceUser:
		return "users", "id"
	case ds.ResourceContactMethod:
		return "user_contact_methods", "id"
	case ds.ResourceNotificationRule:
		return "user_notification_rules", "id"
	case ds.ResourceIntegrationKey:
		return "integration_keys", "audit_resource_id"
	case ds.ResourceUserOverride:
		return "user_overrides", "id"
	default:
		panic("unvalidated deletion kind")
	}
}
