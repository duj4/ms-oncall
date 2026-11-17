package graphqlapp

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/escalation"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/internal/updateguard"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation/validate"
)

const updateVersionDomain = "goalert.update-induced-deletion.v1\x00"

type updateAssessment struct {
	operation ds.Operation
	root      ds.Resource
	plan      ds.DeletionPlan
	removed   []ds.Resource
	selected  []ds.Resource
	expected  map[string]updateConsent
	digest    string
}

func updateObject(kind ds.ResourceKind, id string) ds.Resource {
	return ds.Resource{Kind: kind, ID: id}
}

// These are the same three input types accepted by the existing mutations.
// Confirmation is excluded; a preview cannot acknowledge itself.
func updateIntent(input any) (any, ds.Operation, ds.Resource, error) {
	switch i := input.(type) {
	case graphql2.UpdateEscalationPolicyInput:
		i.Confirmation = nil
		return i, ds.OperationUpdateEscalationPolicy, updateObject(ds.ResourceEscalationPolicy, i.ID), nil
	case graphql2.UpdateEscalationPolicyStepInput:
		i.Confirmation = nil
		i.Targets = nil // compatibility resolver has already materialized Actions
		i.Actions = slices.Clone(i.Actions)
		slices.SortFunc(i.Actions, func(a, b gadb.DestV1) int {
			aa, _ := json.Marshal(a)
			bb, _ := json.Marshal(b)
			return strings.Compare(string(aa), string(bb))
		})
		return i, ds.OperationUpdateEscalationPolicyStep, updateObject(ds.ResourceEscalationPolicyStep, i.ID), nil
	case graphql2.ScheduleTargetInput:
		i.Confirmation = nil
		if i.ScheduleID == nil || i.Target == nil {
			return nil, 0, ds.Resource{}, previewUnavailable()
		}
		target := *i.Target
		if target.Type == assignment.TargetTypeUser && target.ID == "__current_user" {
			return nil, 0, ds.Resource{}, previewUnavailable()
		}
		i.Target = &target
		i.Rules = append([]graphql2.ScheduleRuleInput{}, i.Rules...)
		return i, ds.OperationUpdateScheduleTarget, updateObject(ds.ResourceSchedule, *i.ScheduleID), nil
	}
	return nil, 0, ds.Resource{}, previewUnavailable()
}

func (a *App) assessUpdate(ctx context.Context, tx *sql.Tx, raw any, locked bool) (updateAssessment, error) {
	input, op, root, err := updateIntent(raw)
	s := updateAssessment{operation: op, root: root}
	if err != nil {
		return s, err
	}
	if err := validate.UUID("ID", root.ID); err != nil {
		return s, err
	}
	var authorityErr error
	if op == ds.OperationUpdateScheduleTarget {
		_, authorityErr = scheduleRotationManagementAuthority(ctx, scheduleRotationManagementUpdate)
	} else {
		_, authorityErr = epManagementAuthority(ctx, epManagementUpdate)
	}
	if authorityErr != nil {
		return s, previewUnavailable()
	}
	var before string
	var org uuid.UUID
	var query string
	switch op {
	case ds.OperationUpdateEscalationPolicy:
		query = `SELECT organization_id,jsonb_build_array(id,organization_id,name,description,repeat)::text FROM escalation_policies WHERE id=$1`
	case ds.OperationUpdateEscalationPolicyStep:
		query = `SELECT p.organization_id,jsonb_build_array(s.id,s.escalation_policy_id,s.delay,s.step_number,s.multi_ack,p.organization_id)::text FROM escalation_policy_steps s JOIN escalation_policies p ON p.id=s.escalation_policy_id WHERE s.id=$1`
	case ds.OperationUpdateScheduleTarget:
		query = `SELECT organization_id,jsonb_build_array(id,organization_id,name,description,time_zone)::text FROM schedules WHERE id=$1`
	}
	if err := tx.QueryRowContext(ctx, query, root.ID).Scan(&org, &before); err != nil {
		return s, safePreviewError(err)
	}
	// Scope is corroborated even for a preview of a non-destructive update.
	scope, err := collector.UpdateScope(ctx, tx, org, locked)
	if err != nil {
		return s, err
	}
	if locked {
		if err := lockUpdateChildren(ctx, tx, root); err != nil {
			return s, err
		}
	}
	var rowsState string
	switch i := input.(type) {
	case graphql2.UpdateEscalationPolicyInput:
		policy, readErr := a.PolicyStore.FindOnePolicyTx(ctx, tx, i.ID, &org)
		if readErr != nil {
			return s, safePreviewError(readErr)
		}
		if i.Name != nil {
			policy.Name = *i.Name
		}
		if i.Description != nil {
			policy.Description = *i.Description
		}
		if i.Repeat != nil {
			policy.Repeat = *i.Repeat
		}
		if _, err := policy.Normalize(); err != nil {
			return s, err
		}
		steps, err := a.PolicyStore.FindAllStepsTx(ctx, tx, i.ID)
		if err != nil {
			return s, safePreviewError(err)
		}
		if i.StepIDs != nil {
			ids, err := validate.ParseManyUUID("stepIDs", i.StepIDs, len(steps))
			if err != nil {
				return s, err
			}
			for _, id := range ids {
				if !slices.ContainsFunc(steps, func(step escalation.Step) bool { return step.ID == id }) {
					return s, previewUnavailable()
				}
			}
			for _, step := range steps {
				if !slices.Contains(ids, step.ID) {
					s.removed = append(s.removed, updateObject(ds.ResourceEscalationPolicyStep, step.ID.String()))
				}
			}
		}
		query = `SELECT jsonb_build_array(
          (SELECT jsonb_agg(jsonb_build_array(id,step_number,delay,multi_ack) ORDER BY id) FROM escalation_policy_steps WHERE escalation_policy_id=$1),
          (SELECT jsonb_agg(jsonb_build_array(a.id,a.escalation_policy_step_id,a.user_id,a.schedule_id,a.rotation_id,a.channel_id) ORDER BY a.id) FROM escalation_policy_actions a JOIN escalation_policy_steps st ON st.id=a.escalation_policy_step_id WHERE st.escalation_policy_id=$1))::text`
	case graphql2.UpdateEscalationPolicyStepInput:
		if i.DelayMinutes != nil {
			if err := validate.Range("DelayMinutes", *i.DelayMinutes, 1, 9000); err != nil {
				return s, err
			}
		}
		if i.Actions != nil {
			existing, err := a.PolicyStore.FindAllStepActionsTx(ctx, tx, uuid.MustParse(i.ID))
			if err != nil {
				return s, safePreviewError(err)
			}
			// Preserve the legacy destination equality and DELETE predicate. IDs
			// are resolved by the existing Store; never supplied by the client.
			for _, old := range existing {
				if slices.ContainsFunc(i.Actions, func(next gadb.DestV1) bool { return reflect.DeepEqual(old, next) }) {
					continue
				}
				ids, err := a.PolicyStore.StepActionDeleteIDsTx(ctx, tx, uuid.MustParse(i.ID), old)
				if err != nil {
					return s, safePreviewError(err)
				}
				for _, id := range ids {
					r := updateObject(ds.ResourceEscalationPolicyAction, id.String())
					if !slices.Contains(s.removed, r) {
						s.removed = append(s.removed, r)
					}
				}
			}
		}
		query = `SELECT COALESCE(jsonb_agg(jsonb_build_array(id,escalation_policy_step_id,user_id,schedule_id,rotation_id,channel_id) ORDER BY id),'[]'::jsonb)::text FROM escalation_policy_actions WHERE escalation_policy_step_id=$1`
	case graphql2.ScheduleTargetInput:
		rules, err := a.RuleStore.FindByTargetTx(ctx, tx, *i.ScheduleID, i.Target)
		if err != nil {
			return s, safePreviewError(err)
		}
		if len(i.Rules) < len(rules) {
			for _, r := range rules[len(i.Rules):] {
				s.removed = append(s.removed, updateObject(ds.ResourceScheduleRule, r.ID))
			}
		}
		query = `SELECT COALESCE(jsonb_agg(jsonb_build_array(id,tgt_user_id,tgt_rotation_id,created_at,start_time,end_time,sunday,monday,tuesday,wednesday,thursday,friday,saturday) ORDER BY created_at,id),'[]'::jsonb)::text FROM schedule_rules WHERE schedule_id=$1`
	}
	if err := tx.QueryRowContext(ctx, query, root.ID).Scan(&rowsState); err != nil {
		return s, safePreviewError(err)
	}
	intentJSON, err := json.Marshal(input)
	if err != nil {
		return s, previewUnavailable()
	}
	domainVersion := ""
	desiredState := ""
	if len(s.removed) > 0 {
		if stepInput, ok := input.(graphql2.UpdateEscalationPolicyStepInput); ok {
			desiredState, err = a.validateUpdateActions(ctx, tx, stepInput, org, locked)
			if err != nil {
				return s, err
			}
		}
		purpose := collector.Preview
		if locked {
			purpose = collector.Recheck
		}
		result, err := collector.CollectUpdate(ctx, tx, root, s.removed, purpose, func(_ context.Context, _ *sql.Tx, t collector.Target) error {
			if t.Resource() != root || t.OrganizationID() != org {
				return previewUnavailable()
			}
			return nil
		})
		if err != nil {
			return s, err
		}
		s.selected = slices.Clone(s.removed)
		intents := make([]ds.DestructiveChange, len(s.removed))
		for n, r := range s.removed {
			intents[n] = ds.DestructiveChange{Resource: r, Kind: ds.ChangeDeleted}
		}
		s.plan, err = ds.BuildPlan(ds.PlanInput{Operation: op, Targets: s.removed, Intent: intents, Collection: result.Collection, ScopeFingerprint: result.ScopeFingerprint}, ds.Budget{})
		if err != nil {
			return s, err
		}
		if s.plan.CanProceed() {
			if err := checkUpdateFeasibility(op, s.plan); err != nil {
				return s, err
			}
		}
		if s.plan.CanProceed() {
			s.expected, err = s.auditFeasibility(ctx, tx)
			if err != nil {
				return s, err
			}
		}
		domainVersion = s.plan.ImpactVersion()
		for _, c := range s.plan.Changes() {
			s.removed = appendUniqueUpdateObject(s.removed, c.Resource)
		}
	}
	manifest, _ := json.Marshal([]string{ds.PolicyVersion, scope, hexDigest(intentJSON), before, rowsState, domainVersion, desiredState})
	s.digest = hexDigest(manifest)
	return s, nil
}

func appendUniqueUpdateObject(all []ds.Resource, r ds.Resource) []ds.Resource {
	if !slices.Contains(all, r) {
		return append(all, r)
	}
	return all
}

// A closed B2 audit shape is an execution capability. Runtime/history effects
// absent from SD10 cannot be silently discarded just because the policy allows.
func checkUpdateFeasibility(op ds.Operation, plan ds.DeletionPlan) error {
	for _, c := range plan.Changes() {
		allowed := op == ds.OperationUpdateEscalationPolicy && (c.Resource.Kind == ds.ResourceEscalationPolicyStep || c.Resource.Kind == ds.ResourceEscalationPolicyAction) || op == ds.OperationUpdateEscalationPolicyStep && c.Resource.Kind == ds.ResourceEscalationPolicyAction || op == ds.OperationUpdateScheduleTarget && c.Resource.Kind == ds.ResourceScheduleRule
		if c.Kind != ds.ChangeDeleted || !allowed {
			return previewUnavailable()
		}
	}
	return nil
}

func lockUpdateRows(ctx context.Context, tx *sql.Tx, query string, args ...any) error {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return safePreviewError(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return previewUnavailable()
		}
		n++
		if n > collector.DefaultLimits().MaxRows {
			return previewLimit()
		}
	}
	if rows.Err() != nil {
		return previewUnavailable()
	}
	return nil
}

// The owning mutation already holds its real root row. Incoming FKs are fenced
// by that lock; existing children are locked before the separate diff read.
func lockUpdateChildren(ctx context.Context, tx *sql.Tx, root ds.Resource) error {
	var queries []string
	switch root.Kind {
	case ds.ResourceEscalationPolicy:
		queries = []string{
			`SELECT id::text FROM escalation_policy_steps WHERE escalation_policy_id=$1 ORDER BY id FOR UPDATE NOWAIT`,
			`SELECT a.id::text FROM escalation_policy_actions a JOIN escalation_policy_steps s ON s.id=a.escalation_policy_step_id WHERE s.escalation_policy_id=$1 ORDER BY a.id FOR UPDATE OF a NOWAIT`,
			`SELECT es.id::text FROM escalation_policy_state es JOIN escalation_policy_steps s ON s.id=es.escalation_policy_step_id WHERE s.escalation_policy_id=$1 ORDER BY es.id FOR UPDATE OF es NOWAIT`,
			`SELECT a.id::text FROM alerts a WHERE id IN (SELECT es.alert_id FROM escalation_policy_state es JOIN escalation_policy_steps s ON s.id=es.escalation_policy_step_id WHERE s.escalation_policy_id=$1) ORDER BY a.id FOR SHARE NOWAIT`,
			`SELECT h.id::text FROM ep_step_on_call_users h JOIN escalation_policy_steps s ON s.id=h.ep_step_id WHERE s.escalation_policy_id=$1 ORDER BY h.id FOR UPDATE OF h NOWAIT`,
		}
	case ds.ResourceEscalationPolicyStep:
		queries = []string{
			`SELECT p.id::text FROM escalation_policies p JOIN escalation_policy_steps s ON s.escalation_policy_id=p.id WHERE s.id=$1 FOR SHARE OF p NOWAIT`,
			`SELECT id::text FROM escalation_policy_actions WHERE escalation_policy_step_id=$1 ORDER BY id FOR UPDATE NOWAIT`,
		}
	case ds.ResourceSchedule:
		queries = []string{`SELECT id::text FROM schedule_rules WHERE schedule_id=$1 ORDER BY id FOR UPDATE NOWAIT`}
	}
	for _, q := range queries {
		if err := lockUpdateRows(ctx, tx, q, root.ID); err != nil {
			return err
		}
	}
	// Target SHARE is NOWAIT: competing root deletion may own the target first.
	// This yields a bounded safety refusal instead of inverting its lock order.
	var source string
	switch root.Kind {
	case ds.ResourceEscalationPolicy:
		source = `SELECT a.user_id AS uid,a.schedule_id AS sid,a.rotation_id AS rid FROM escalation_policy_actions a JOIN escalation_policy_steps s ON s.id=a.escalation_policy_step_id WHERE s.escalation_policy_id=$1`
	case ds.ResourceEscalationPolicyStep:
		source = `SELECT user_id AS uid,schedule_id AS sid,rotation_id AS rid FROM escalation_policy_actions WHERE escalation_policy_step_id=$1`
	case ds.ResourceSchedule:
		source = `SELECT tgt_user_id AS uid,NULL::uuid AS sid,tgt_rotation_id AS rid FROM schedule_rules WHERE schedule_id=$1`
	}
	for _, q := range []string{
		`SELECT u.id::text FROM users u WHERE u.id IN (SELECT uid FROM (` + source + `) f) ORDER BY u.id FOR SHARE NOWAIT`,
		`SELECT u.user_id::text FROM user_organization_assignments u WHERE u.user_id IN (SELECT uid FROM (` + source + `) f) ORDER BY u.user_id FOR SHARE NOWAIT`,
		`SELECT s.id::text FROM schedules s WHERE s.id IN (SELECT sid FROM (` + source + `) f) ORDER BY s.id FOR SHARE NOWAIT`,
		`SELECT r.id::text FROM rotations r WHERE r.id IN (SELECT rid FROM (` + source + `) f) ORDER BY r.id FOR SHARE NOWAIT`,
	} {
		if err := lockUpdateRows(ctx, tx, q, root.ID); err != nil {
			return err
		}
	}
	return nil
}

func (s updateAssessment) enforce(ctx context.Context, tx *sql.Tx, signer DeletionCursorSigner, c *graphql2.DeletionSafetyConfirmationInput) (context.Context, error) {
	destructive := len(s.removed) > 0
	if destructive && !s.plan.CanProceed() {
		return ctx, s.plan.Check("", false)
	}
	if destructive && (c == nil || !c.AcknowledgeImpacts || c.ExpectedImpactVersion == "") {
		return ctx, &ds.DeletionSafetyError{Code: ds.DeletionConfirmationRequired}
	}
	if c != nil && c.ExpectedImpactVersion != "" {
		if len(c.ExpectedImpactVersion) > 2048 {
			return ctx, &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
		}
		digest, rawSig, ok := strings.Cut(c.ExpectedImpactVersion, ".")
		signature, err := base64.RawURLEncoding.DecodeString(rawSig)
		if !ok || err != nil || signer == nil || digest != s.digest {
			return ctx, &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
		}
		valid, _ := signer.Verify([]byte(updateVersionDomain+digest), signature)
		if !valid {
			return ctx, &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
		}
	}
	if !destructive {
		return ctx, nil
	}
	if err := s.plan.Check(s.plan.ImpactVersion(), true); err != nil {
		return ctx, err
	}
	return updateguard.Bind(ctx, tx, s.removed)
}

func safeUpdateResource(r ds.Resource) *graphql2.DeletionResource {
	kind := previewResourceNames[r.Kind]
	return &graphql2.DeletionResource{ID: r.ID, Type: kind, Label: kind + " " + r.ID}
}

func (q *Query) previewUpdate(ctx context.Context, input any) (_ *graphql2.UpdateDeletionPreview, err error) {
	if q.DB == nil || q.PreviewSigner == nil || hasInheritedContextTx(ctx) {
		return nil, previewUnavailable()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := q.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, previewUnavailable()
	}
	defer func() { _ = tx.Rollback() }()
	s, err := (*App)(q).assessUpdate(ctx, tx, input, false)
	if err != nil {
		return nil, safePreviewError(err)
	}
	sig, err := q.PreviewSigner.Sign([]byte(updateVersionDomain + s.digest))
	if err != nil {
		return nil, previewUnavailable()
	}
	response := &graphql2.UpdateDeletionPreview{Root: safeUpdateResource(s.root), PolicyVersion: ds.PolicyVersion, Complete: true, CanProceed: true, ImpactVersion: s.digest + "." + base64.RawURLEncoding.EncodeToString(sig), Removed: []graphql2.DeletionResource{}, Impacts: []graphql2.DeletionImpact{}}
	response.Operation = map[ds.Operation]graphql2.DeletionOperation{ds.OperationUpdateEscalationPolicy: graphql2.DeletionOperationUpdateEscalationPolicy, ds.OperationUpdateEscalationPolicyStep: graphql2.DeletionOperationUpdateEscalationPolicyStep, ds.OperationUpdateScheduleTarget: graphql2.DeletionOperationUpdateScheduleTarget}[s.operation]
	if len(s.removed) > 0 {
		response.CanProceed = s.plan.CanProceed()
		response.RequiresConfirmation = response.CanProceed && s.plan.RequiresConfirmation()
		for _, r := range s.removed {
			response.Removed = append(response.Removed, *safeUpdateResource(r))
		}
		authority := previewAuthority{ctx: ctx, system: permission.System(ctx)}
		for _, d := range s.plan.Impacts() {
			policies := map[ds.DeletionPolicy]graphql2.DeletionPolicy{ds.PolicyBlock: graphql2.DeletionPolicyBlock, ds.PolicyWarning: graphql2.DeletionPolicyWarning, ds.PolicyCascade: graphql2.DeletionPolicyCascade, ds.PolicyInformational: graphql2.DeletionPolicyInformational}
			impact := graphql2.DeletionImpact{EdgeID: d.EdgeID, Target: safeUpdateResource(d.Target), ReferencingResource: safeUpdateResource(d.Referencing), Relation: previewRelationshipNames[d.Relationship], Change: previewChangeNames[d.Change], Policy: policies[d.Policy], Impact: deletionImpactDescription(d), RequiredAction: previewActionNames[d.RequiredAction], CanModifyReference: authority.canModify(d.Referencing, d.Owner), IsDerived: d.IsDerived, IsPlannedCoDeletion: d.IsPlannedCoDeletion}
			if d.Parent.Kind != ds.ResourceUnknown {
				impact.Parent = safeUpdateResource(d.Parent)
			}
			response.Impacts = append(response.Impacts, impact)
		}
	}
	if err := tx.Rollback(); err != nil {
		return nil, previewUnavailable()
	}
	return response, nil
}

func (q *Query) PreviewUpdateEscalationPolicy(ctx context.Context, input graphql2.UpdateEscalationPolicyInput) (*graphql2.UpdateDeletionPreview, error) {
	return q.previewUpdate(ctx, input)
}
func (q *Query) PreviewUpdateEscalationPolicyStep(ctx context.Context, input graphql2.UpdateEscalationPolicyStepInput) (*graphql2.UpdateDeletionPreview, error) {
	return q.previewUpdate(ctx, input)
}
func (q *Query) PreviewUpdateScheduleTarget(ctx context.Context, input graphql2.ScheduleTargetInput) (*graphql2.UpdateDeletionPreview, error) {
	if input.Target != nil && input.Target.Type == assignment.TargetTypeUser && input.Target.ID == "__current_user" {
		target := *input.Target
		target.ID = permission.UserID(ctx)
		input.Target = &target
	}
	return q.previewUpdate(ctx, input)
}

func hasUpdateConfirmation(c *graphql2.DeletionSafetyConfirmationInput) bool {
	return c != nil && c.ExpectedImpactVersion != ""
}

// Ordinary updates keep their existing Store validation and admission. Only a
// real server-observed removal (or a supplied version needing revalidation)
// enters the additional deletion protocol. An unexpected later removal still
// fails at the Store because this fast path grants no child-delete capability.
func (m *Mutation) policyUpdateNeedsSafety(ctx context.Context, tx *sql.Tx, input graphql2.UpdateEscalationPolicyInput) (bool, error) {
	if hasUpdateConfirmation(input.Confirmation) {
		return true, nil
	}
	if input.StepIDs == nil {
		return false, nil
	}
	steps, err := m.PolicyStore.FindAllStepsTx(ctx, tx, input.ID)
	if err != nil {
		return false, err
	}
	ids, err := validate.ParseManyUUID("stepIDs", input.StepIDs, len(steps))
	if err != nil {
		return true, nil
	}
	for _, step := range steps {
		if !slices.Contains(ids, step.ID) {
			return true, nil
		}
	}
	return false, nil
}
func (m *Mutation) stepUpdateNeedsSafety(ctx context.Context, tx *sql.Tx, input graphql2.UpdateEscalationPolicyStepInput) (bool, error) {
	if hasUpdateConfirmation(input.Confirmation) {
		return true, nil
	}
	if input.Actions == nil {
		return false, nil
	}
	id, err := validate.ParseUUID("ID", input.ID)
	if err != nil {
		return true, nil
	}
	// Freeze existing destination rows before declaring the fast path harmless.
	// Step FOR UPDATE fences incoming actions, but a target-only UPDATE need
	// not take that FK lock. This also keeps an inherited owner from observing
	// a new removal after it has already staged ordinary scalar changes.
	if err := lockUpdateRows(ctx, tx, `SELECT id::text FROM escalation_policy_actions WHERE escalation_policy_step_id=$1 ORDER BY id FOR UPDATE NOWAIT`, id); err != nil {
		return false, err
	}
	existing, err := m.PolicyStore.FindAllStepActionsTx(ctx, tx, id)
	if err != nil {
		return false, err
	}
	for _, old := range existing {
		if !slices.ContainsFunc(input.Actions, func(next gadb.DestV1) bool { return reflect.DeepEqual(old, next) }) {
			return true, nil
		}
	}
	return false, nil
}
