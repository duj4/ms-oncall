package graphqlapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/internal/updateguard"
	"github.com/target/goalert/schedule/rotation"
	"github.com/target/goalert/schedule/updateaudit"
	"github.com/target/goalert/util"
	"github.com/target/goalert/validation"
	"github.com/target/goalert/validation/validate"
)

// Both Preview and Mutation apply precisely the existing scalar semantics.
func rotationUpdateFields(r *rotation.Rotation, i graphql2.UpdateRotationInput) (bool, error) {
	changed := i.Name != nil || i.Description != nil || i.Start != nil || i.Type != nil || i.ShiftLength != nil || i.TimeZone != nil
	if i.Name != nil {
		r.Name = *i.Name
	}
	if i.Description != nil {
		r.Description = *i.Description
	}
	if i.Start != nil {
		r.Start = *i.Start
	}
	if i.Type != nil {
		r.Type = *i.Type
	}
	if i.ShiftLength != nil {
		r.ShiftLength = *i.ShiftLength
	}
	if i.TimeZone != nil {
		loc, err := util.LoadLocation(*i.TimeZone)
		if err != nil {
			return false, validation.NewFieldError("TimeZone", "invalid TimeZone: "+err.Error())
		}
		r.Start = r.Start.In(loc)
	}
	if changed {
		if _, err := r.Normalize(); err != nil {
			return false, err
		}
	}
	return changed, nil
}

func (a *App) assessRotationUpdate(ctx context.Context, tx *sql.Tx, input graphql2.UpdateRotationInput, locked bool) (updateAssessment, error) {
	s := updateAssessment{operation: ds.OperationUpdateRotation, root: updateObject(ds.ResourceRotation, input.ID)}
	if _, err := scheduleRotationManagementAuthority(ctx, scheduleRotationManagementUpdate); err != nil {
		return s, previewUnavailable()
	}
	// Admission precedes any private roster projection. The current actor and
	// target organization are corroborated again in the actual SQL snapshot.
	var org uuid.UUID
	var rootState string
	if err := tx.QueryRowContext(ctx, `SELECT organization_id,jsonb_build_array(id,organization_id,name,description,type,start_time,shift_length,time_zone)::text FROM rotations WHERE id=$1`, input.ID).Scan(&org, &rootState); err != nil {
		return s, safePreviewError(err)
	}
	scope, err := collector.UpdateScope(ctx, tx, org, locked)
	if err != nil {
		return s, err
	}
	r, err := a.RotationStore.FindRotationTx(ctx, tx, input.ID, &org)
	if err != nil {
		return s, safePreviewError(err)
	}
	if _, err := rotationUpdateFields(r, input); err != nil {
		return s, err
	}
	before, err := updateaudit.CaptureRotation(ctx, tx, uuid.MustParse(input.ID))
	if err != nil {
		return s, previewUnavailable()
	}
	if len(before.Participants) > collector.DefaultLimits().MaxRows || len(input.UserIDs) > collector.DefaultLimits().MaxRows {
		return s, previewLimit()
	}
	s.rotationBefore = before
	want := len(before.Participants)
	if input.UserIDs != nil {
		want = len(input.UserIDs)
	}
	if input.ActiveUserIndex != nil && before.State != nil && want > 0 {
		if err := validate.Range("ActiveUserIndex", *input.ActiveUserIndex, 0, want-1); err != nil {
			return s, err
		}
	}
	if input.UserIDs != nil && want < len(before.Participants) {
		for _, p := range before.Participants[want:] {
			s.selected = append(s.selected, updateObject(ds.ResourceRotationParticipant, p.ID.String()))
		}
		s.removed = slices.Clone(s.selected)
	}
	// Match the existing Store's per-call identity limits before promising DML.
	if len(s.selected) > 50 || want-len(before.Participants) > 50 {
		return s, previewLimit()
	}
	users := slices.Clone(input.UserIDs)
	for _, p := range before.Participants {
		users = append(users, p.UserID.String())
	}
	userState, err := a.rotationUpdateUsers(ctx, tx, org, users, locked)
	if err != nil {
		return s, err
	}
	dependencies, err := rotationUpdateDependencies(ctx, tx, input.ID, locked)
	if err != nil {
		return s, err
	}
	domainVersion := ""
	if len(s.selected) != 0 {
		purpose := collector.Preview
		if locked {
			purpose = collector.Recheck
		}
		facts, err := collector.CollectUpdate(ctx, tx, s.root, s.selected, purpose, func(_ context.Context, _ *sql.Tx, target collector.Target) error {
			if target.Resource() != s.root || target.OrganizationID() != org {
				return previewUnavailable()
			}
			return nil
		})
		if err != nil {
			return s, err
		}
		intents := make([]ds.DestructiveChange, len(s.selected))
		for n, child := range s.selected {
			intents[n] = ds.DestructiveChange{Resource: child, Kind: ds.ChangeDeleted}
		}
		s.plan, err = ds.BuildPlan(ds.PlanInput{Operation: s.operation, Targets: s.selected, Intent: intents, Collection: facts.Collection, ScopeFingerprint: facts.ScopeFingerprint}, ds.Budget{})
		if err != nil {
			return s, err
		}
		for _, c := range s.plan.Changes() {
			if c.Resource.Kind != ds.ResourceRotationParticipant || c.Kind != ds.ChangeDeleted || !slices.Contains(s.selected, c.Resource) {
				return s, previewUnavailable()
			}
		}
		domainVersion = s.plan.ImpactVersion()
		// U04 already audits State clear using complete Before/After snapshots.
		// Declare its real identity in the confirmed removal set as well. This
		// is existing explicit SQL, not a new Root selector or FK cascade rule.
		if want == 0 && before.State != nil {
			s.removed = append(s.removed, updateObject(ds.ResourceRotationState, strconv.FormatInt(before.State.ID, 10)))
		}
	}
	input.Confirmation = nil
	manifest, err := json.Marshal([]any{ds.PolicyVersion, scope, input, rootState, before, userState, dependencies, domainVersion, s.removed})
	if err != nil {
		return s, previewUnavailable()
	}
	s.digest = hexDigest(manifest)
	return s, nil
}

func (a *App) rotationUpdateUsers(ctx context.Context, tx *sql.Tx, org uuid.UUID, users []string, locked bool) (string, error) {
	for _, id := range users {
		if err := validate.UUID("UserIDs", id); err != nil {
			return "", err
		}
	}
	// Duplicates are legitimate distinct positions; deduplicate only this lock
	// and scope projection, never the desired roster or persisted identities.
	ids := slices.Clone(users)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if locked && len(ids) > 0 {
		for _, q := range []string{
			`SELECT id::text FROM users WHERE id=ANY($1::uuid[]) ORDER BY id FOR SHARE NOWAIT`,
			`SELECT user_id::text FROM user_organization_assignments WHERE user_id=ANY($1::uuid[]) ORDER BY user_id FOR SHARE NOWAIT`,
		} {
			if err := lockUpdateRows(ctx, tx, q, pq.Array(ids)); err != nil {
				return "", err
			}
		}
	}
	if err := (*Mutation)(a).validateRotationUsers(ctx, tx, org, ids); err != nil {
		return "", previewUnavailable()
	}
	var state string
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_array(u.id,u.role,a.effective_organization_id,a.organization_role,a.mapping_outcome,a.matched_count) ORDER BY u.id),'[]'::jsonb)::text FROM users u LEFT JOIN user_organization_assignments a ON a.user_id=u.id WHERE u.id=ANY($1::uuid[])`, pq.Array(ids)).Scan(&state)
	if err != nil {
		return "", safePreviewError(err)
	}
	return state, nil
}

// The Rotation FOR UPDATE fences incoming FKs. Lock existing references and
// their surviving owners with NOWAIT to avoid reversing Root Delete lock order.
// Schedule JSON contains User/Channel references, no Participant or Rotation
// identities. Its writers may commute; they do not change this deletion diff.
func rotationUpdateDependencies(ctx context.Context, tx *sql.Tx, id string, locked bool) (string, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM schedule_rules WHERE tgt_rotation_id=$1)+(SELECT count(*) FROM escalation_policy_actions WHERE rotation_id=$1)`, id).Scan(&count); err != nil {
		return "", safePreviewError(err)
	}
	if count > collector.DefaultLimits().MaxRows {
		return "", previewLimit()
	}
	if locked {
		for _, q := range []string{
			`SELECT id::text FROM schedule_rules WHERE tgt_rotation_id=$1 ORDER BY id FOR SHARE NOWAIT`,
			`SELECT id::text FROM escalation_policy_actions WHERE rotation_id=$1 ORDER BY id FOR SHARE NOWAIT`,
			`SELECT s.id::text FROM schedules s WHERE id IN (SELECT schedule_id FROM schedule_rules WHERE tgt_rotation_id=$1) ORDER BY s.id FOR SHARE NOWAIT`,
			`SELECT p.id::text FROM escalation_policies p WHERE id IN (SELECT s.escalation_policy_id FROM escalation_policy_steps s JOIN escalation_policy_actions a ON a.escalation_policy_step_id=s.id WHERE a.rotation_id=$1) ORDER BY p.id FOR SHARE NOWAIT`,
			`SELECT s.id::text FROM escalation_policy_steps s WHERE id IN (SELECT escalation_policy_step_id FROM escalation_policy_actions WHERE rotation_id=$1) ORDER BY s.id FOR SHARE NOWAIT`,
		} {
			if err := lockUpdateRows(ctx, tx, q, id); err != nil {
				return "", err
			}
		}
	}
	var state string
	err := tx.QueryRowContext(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(jsonb_build_array(r.id,r.schedule_id,r.start_time,r.end_time,r.sunday,r.monday,r.tuesday,r.wednesday,r.thursday,r.friday,r.saturday,s.organization_id,s.time_zone) ORDER BY r.id) FROM schedule_rules r JOIN schedules s ON s.id=r.schedule_id WHERE r.tgt_rotation_id=$1),
 (SELECT jsonb_agg(jsonb_build_array(a.id,a.escalation_policy_step_id,p.id,p.organization_id,s.step_number,s.delay,s.multi_ack) ORDER BY a.id) FROM escalation_policy_actions a JOIN escalation_policy_steps s ON s.id=a.escalation_policy_step_id JOIN escalation_policies p ON p.id=s.escalation_policy_id WHERE a.rotation_id=$1))::text`, id).Scan(&state)
	if err != nil {
		return "", safePreviewError(err)
	}
	return state, nil
}

// Compare actual SQL receipts and the accepted U04 snapshots before its sole
// appender runs. All survivors must match the real positional Update intent.
func (s updateAssessment) finishRotation(ctx context.Context, tx *sql.Tx, input graphql2.UpdateRotationInput, after *updateaudit.RotationSnapshot, receipts []rotation.ParticipantDeleteReceipt) error {
	changed := func() error { return &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged} }
	before := s.rotationBefore
	if before == nil || after == nil || len(receipts) != len(s.selected) || len(after.Participants) != len(input.UserIDs) {
		return changed()
	}
	seen := map[uuid.UUID]bool{}
	for _, r := range receipts {
		if seen[r.ID] || r.RotationID.String() != s.root.ID || !slices.Contains(s.selected, updateObject(ds.ResourceRotationParticipant, r.ID.String())) {
			return changed()
		}
		seen[r.ID] = true
		if !slices.ContainsFunc(before.Participants, func(p updateaudit.Participant) bool { return p.ID == r.ID && p.UserID == r.UserID }) {
			return changed()
		}
	}
	for n, p := range after.Participants {
		if p.ID != before.Participants[n].ID || p.UserID != uuid.MustParse(input.UserIDs[n]) || int(p.Position) != n {
			return changed()
		}
	}
	if len(after.Participants) == 0 {
		if after.State != nil {
			return changed()
		}
	} else {
		if before.State == nil || after.State == nil || before.State.ID != after.State.ID || before.State.Version != after.State.Version {
			return changed()
		}
		position := int(before.State.Position)
		if position >= len(after.Participants) {
			position = 0
		}
		if input.ActiveUserIndex != nil {
			position = *input.ActiveUserIndex
		}
		if int(after.State.Position) != position || after.State.ParticipantID != after.Participants[position].ID {
			return changed()
		}
		shift := before.State.ShiftStart
		if input.Name != nil || input.Description != nil || input.Start != nil || input.Type != nil || input.ShiftLength != nil || input.TimeZone != nil {
			var now time.Time
			if err := tx.QueryRowContext(ctx, `SELECT transaction_timestamp()`).Scan(&now); err != nil {
				return previewUnavailable()
			}
			shift = now
		}
		if !after.State.ShiftStart.Equal(shift) {
			return changed()
		}
	}
	return updateguard.Complete(ctx, tx)
}

func (m *Mutation) rotationUpdateNeedsSafety(ctx context.Context, tx *sql.Tx, input graphql2.UpdateRotationInput) (bool, error) {
	if hasUpdateConfirmation(input.Confirmation) {
		return true, nil
	}
	if input.UserIDs == nil {
		return false, nil
	}
	parts, err := m.RotationStore.FindAllParticipantsTx(ctx, tx, input.ID)
	return len(input.UserIDs) < len(parts), err
}
