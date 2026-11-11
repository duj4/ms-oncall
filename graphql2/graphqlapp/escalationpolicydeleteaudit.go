package graphqlapp

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/target/goalert/escalation"
	epaudit "github.com/target/goalert/escalation/deleteaudit"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation/validate"
)

func (a *deleteAllAttempt) epCaptureError(err error) error {
	if err != nil {
		pg := sqlutil.MapError(err)
		if pg == nil || pg.Code != "40001" && pg.Code != "40P01" {
			a.auditFailed = true
		}
	}
	return err
}

// Capture runs only when the original EP group is reached. Earlier groups' child
// deletions cannot become EP cascade effects. No table lock is added here.
func (a *deleteAllAttempt) captureEP(ctx context.Context, ids []string, scope *uuid.UUID) (err error) {
	parsed, err := validate.ParseManyUUID("EscalationPolicyID", ids, 50)
	if err != nil {
		return err
	}
	slices.SortFunc(parsed, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	parsed = slices.Compact(parsed)
	defer func() { err = a.epCaptureError(err) }()
	q := `SELECT id FROM escalation_policies WHERE id=ANY($1::uuid[])`
	args := []any{pq.Array(parsed)}
	if scope != nil {
		q += ` AND organization_id=$2`
		args = append(args, *scope)
	}
	rows, err := a.tx.QueryContext(ctx, q+` ORDER BY id FOR UPDATE`, args...)
	if err != nil {
		return err
	}
	var roots []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			break
		}
		roots = append(roots, id)
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return err
	}
	// New statement after the lock wait: attribution is the locked row's value.
	rows, err = a.tx.QueryContext(ctx, `SELECT id,organization_id FROM escalation_policies WHERE id=ANY($1::uuid[]) ORDER BY id`, pq.Array(roots))
	if err != nil {
		return err
	}
	for rows.Next() {
		e := a.epEvent
		if err = rows.Scan(&e.RootID, &e.TargetOrganizationID); err != nil {
			break
		}
		if scope != nil && e.TargetOrganizationID != *scope {
			err = epaudit.ErrInvalid
			break
		}
		e.EventID, e.TargetOrgResolution = uuid.New(), "known_normal"
		a.epTargets = append(a.epTargets, e)
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return err
	}
	if len(a.epTargets) != len(roots) {
		return epaudit.ErrInvalid
	}
	a.epBytes = 2 * len(roots)
	for _, typ := range []string{epaudit.Step, epaudit.Action, epaudit.Favorite} {
		if err = a.captureEPChildren(ctx, roots, typ); err != nil {
			return err
		}
	}
	return nil
}

func epChildTable(typ string) (table, parent string) {
	switch typ {
	case epaudit.Step:
		return "escalation_policy_steps", "escalation_policy_id"
	case epaudit.Action:
		return "escalation_policy_actions", "escalation_policy_step_id"
	case epaudit.Favorite:
		return "user_favorites", "tgt_escalation_policy_id"
	default:
		panic("invalid internal EP effect type")
	}
}

func (a *deleteAllAttempt) epSteps() []uuid.UUID {
	result := []uuid.UUID{}
	for _, f := range a.epChildren {
		if f.ResourceType == epaudit.Step {
			result = append(result, *f.ResourceUUID)
		}
	}
	return result
}

func (a *deleteAllAttempt) captureEPChildren(ctx context.Context, roots []uuid.UUID, typ string) error {
	table, parent := epChildTable(typ)
	parents := roots
	if typ == epaudit.Action {
		parents = a.epSteps()
	}
	// LIMIT bounds both server result materialization and Go identities. One extra
	// row proves overflow, before reading an unbounded child model/projection.
	rows, err := a.tx.QueryContext(ctx, `SELECT id FROM `+table+` WHERE `+parent+`=ANY($1::uuid[]) ORDER BY id LIMIT $2 FOR UPDATE`, pq.Array(parents), epaudit.MaxEffects-len(a.epChildren)+1)
	if err != nil {
		return err
	}
	var uuids []uuid.UUID
	var nums []int64
	for rows.Next() {
		if typ == epaudit.Favorite {
			var id int64
			err = rows.Scan(&id)
			nums = append(nums, id)
		} else {
			var id uuid.UUID
			err = rows.Scan(&id)
			uuids = append(uuids, id)
		}
		if err != nil {
			break
		}
		if len(a.epChildren)+len(uuids)+len(nums) > epaudit.MaxEffects {
			err = epaudit.ErrCapacity
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return err
	}
	// Membership/parents/owners are read again after every child lock wait.
	q := `SELECT id,` + parent
	var identities any = pq.Array(uuids)
	if typ == epaudit.Step {
		q += `,step_number`
	}
	if typ == epaudit.Favorite {
		q += `,user_id`
		identities = pq.Array(nums)
	}
	if typ == epaudit.Action {
		q = `SELECT a.id,a.escalation_policy_step_id,s.escalation_policy_id,
		 CASE WHEN a.user_id IS NOT NULL THEN 'user' WHEN a.schedule_id IS NOT NULL THEN 'schedule' WHEN a.rotation_id IS NOT NULL THEN 'rotation' ELSE 'notification_channel' END,
		 COALESCE(a.user_id,a.schedule_id,a.rotation_id,a.channel_id)
		 FROM escalation_policy_actions a JOIN escalation_policy_steps s ON s.id=a.escalation_policy_step_id
		 WHERE a.id=ANY($1::uuid[]) AND s.id=ANY($2::uuid[]) ORDER BY a.id`
	} else {
		q += ` FROM ` + table + ` WHERE id=ANY($1) AND ` + parent + `=ANY($2::uuid[]) ORDER BY id`
	}
	rows, err = a.tx.QueryContext(ctx, q, identities, pq.Array(parents))
	if err != nil {
		return err
	}
	var captured []epaudit.Effect
	for rows.Next() {
		f := epaudit.Effect{EffectID: uuid.New(), ResourceType: typ, Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: "escalation_policy_delete", Change: "deleted"}
		switch typ {
		case epaudit.Step:
			var id uuid.UUID
			var n int
			err = rows.Scan(&id, &f.RootID, &n)
			f.ResourceUUID, f.StepNumber, f.Relation = &id, &n, "escalation_policy.step"
		case epaudit.Action:
			var id, step, target uuid.UUID
			err = rows.Scan(&id, &step, &f.RootID, &f.TargetKind, &target)
			f.ResourceUUID, f.ParentStepID, f.TargetID, f.Relation = &id, &step, &target, "escalation_policy.step.action"
		case epaudit.Favorite:
			var id int64
			var owner uuid.UUID
			err = rows.Scan(&id, &f.RootID, &owner)
			f.ResourceNumericID, f.OwnerUserID, f.Relation, f.Change = &id, &owner, "escalation_policy.favorite", "relationship_removed"
		}
		if err != nil {
			break
		}
		found := false
		for _, e := range a.epTargets {
			if e.RootID == f.RootID {
				f.TargetOrganizationID = e.TargetOrganizationID
				found = true
				break
			}
		}
		if !found {
			err = epaudit.ErrInvalid
			break
		}
		captured = append(captured, f)
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return err
	}
	owners := map[uuid.UUID]executioncontext.CMNROrganizationSnapshot{}
	ownerIDs := []uuid.UUID{}
	for _, f := range captured {
		if f.OwnerUserID != nil {
			ownerIDs = append(ownerIDs, *f.OwnerUserID)
		}
	}
	slices.SortFunc(ownerIDs, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	for _, owner := range slices.Compact(ownerIDs) {
		o, err := executioncontext.SnapshotCMNROrganization(ctx, a.tx, owner)
		if err != nil {
			return err
		}
		owners[owner] = o
	}
	for _, f := range captured {
		if f.OwnerUserID != nil {
			o := owners[*f.OwnerUserID]
			f.OwnerOrgResolution = o.Resolution
			if o.ID != uuid.Nil {
				id := o.ID
				f.OwnerOrganizationID = &id
			}
		}
		raw, err := json.Marshal(f)
		if err != nil {
			return epaudit.ErrInvalid
		}
		a.epBytes += len(raw) + 1
		if a.epBytes > epaudit.MaxJSONBytes {
			return epaudit.ErrCapacity
		}
		a.epChildren = append(a.epChildren, f)
	}
	var count int
	if err = a.tx.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` WHERE `+parent+`=ANY($1::uuid[])`, pq.Array(parents)).Scan(&count); err != nil {
		return err
	}
	if count != len(captured) {
		return epaudit.ErrInvalid
	}
	return nil
}

func (a *deleteAllAttempt) collectEPReceipts(receipts []escalation.DeleteReceipt) error {
	if len(receipts) > 50 || len(a.epTargets) > 50 {
		return epaudit.ErrCapacity
	}
	seen := map[uuid.UUID]bool{}
	for _, r := range receipts {
		found := false
		for _, e := range a.epTargets {
			if e.RootID == r.ID && e.TargetOrganizationID == r.OrganizationID {
				found = true
				break
			}
		}
		if !found || seen[r.ID] {
			return epaudit.ErrInvalid
		}
		seen[r.ID] = true
	}
	// A captured and locked actual root must have an explicit DELETE receipt.
	if len(receipts) != len(a.epTargets) {
		return epaudit.ErrInvalid
	}
	return nil
}

func (a *deleteAllAttempt) witnessEP(ctx context.Context, receipts []escalation.DeleteReceipt) (err error) {
	defer func() { err = a.epCaptureError(err) }()
	if err = a.collectEPReceipts(receipts); err != nil {
		return err
	}
	for _, e := range a.epTargets {
		var exists bool
		if err = a.tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM escalation_policies WHERE id=$1)`, e.RootID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return epaudit.ErrInvalid
		}
		for _, typ := range []string{epaudit.Step, epaudit.Favorite} {
			table, parent := epChildTable(typ)
			if err = a.tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM `+table+` WHERE `+parent+`=$1)`, e.RootID).Scan(&exists); err != nil {
				return err
			}
			if exists {
				return epaudit.ErrInvalid
			}
		}
		e.RecordKind, e.Outcome, e.Reason = "success_witness", "committed", "deleted"
		e.Provenance, e.DeletionMechanism, e.Cause = "EXPLICIT", "explicit_sql", "explicit_target"
		for _, f := range a.epChildren {
			if f.RootID == e.RootID {
				e.Effects = append(e.Effects, f)
			}
		}
		a.epSuccesses = append(a.epSuccesses, e.Canonical())
	}
	// Verify every captured child identity, including actions whose parent is now
	// absent. Absence alone is insufficient without the locked inventory/receipts.
	for _, f := range a.epChildren {
		table, _ := epChildTable(f.ResourceType)
		var id any = f.ResourceNumericID
		if f.ResourceUUID != nil {
			id = *f.ResourceUUID
		}
		var exists bool
		if err = a.tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM `+table+` WHERE id=$1)`, id).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return epaudit.ErrInvalid
		}
	}
	return epaudit.ValidateBatch(a.epSuccesses)
}

func (a *deleteAllAttempt) appendEP(ctx context.Context) error {
	if !a.plan.hasEP {
		return nil
	}
	if err := epaudit.ValidateBatch(a.epSuccesses); err != nil {
		return err
	}
	for _, e := range a.epSuccesses {
		if err := epaudit.Append(ctx, a.tx, e); err != nil {
			return err
		}
	}
	var roots, count, size int
	if err := a.tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(jsonb_array_length(effects)),0),coalesce(sum(octet_length(effects::text)),0) FROM escalation_policy_delete_audit_events WHERE attempt_id=$1 AND execution_id=$2 AND record_kind='success_witness'`, a.event.AttemptID, a.event.ExecutionID).Scan(&roots, &count, &size); err != nil {
		return err
	}
	if roots != len(a.epSuccesses) || count != len(a.epChildren) {
		return epaudit.ErrInvalid
	}
	if count > epaudit.MaxEffects || size > epaudit.MaxJSONBytes {
		return epaudit.ErrCapacity
	}
	return nil
}

func (a *deleteAllAttempt) epFailureEvents(outcome, reason string) []epaudit.Event {
	if !a.plan.hasEP {
		return nil
	}
	if a.epInUse && outcome == "validation_failed" && reason == "invalid_fields" {
		reason = "target_in_use"
	}
	events := append([]epaudit.Event{}, a.epTargets...)
	if len(events) == 0 {
		events = append(events, a.epEvent)
	}
	for i := range events {
		e := &events[i]
		e.EventID, e.RecordKind, e.Outcome, e.Reason, e.OccurredAt = uuid.New(), "attempt_observation", outcome, reason, time.Now()
		e.Provenance, e.DeletionMechanism, e.Cause = "", "", ""
		e.Effects = nil
	}
	return events
}
