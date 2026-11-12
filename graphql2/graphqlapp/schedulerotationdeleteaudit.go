package graphqlapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/target/goalert/executioncontext"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation/validate"
)

func (a *deleteAllAttempt) srCaptureError(err error) error {
	if err != nil {
		pg := sqlutil.MapError(err)
		if pg == nil || pg.Code != "40001" && pg.Code != "40P01" {
			a.auditFailed = true
		}
	}
	return err
}
func srRootTable(typ string) string {
	if typ == sraudit.Schedule {
		return "schedules"
	}
	if typ == sraudit.Rotation {
		return "rotations"
	}
	panic("invalid SR root type")
}

// Each group captures its current inventory when reached, after earlier groups
// have run. The root lock fences all new FK references, including JSON envelopes.
func (a *deleteAllAttempt) captureSR(ctx context.Context, typ string, ids []string, scope *uuid.UUID) (err error) {
	if a.tx == nil {
		return a.srCaptureError(sraudit.ErrUnavailable)
	}
	field := "ScheduleID"
	if typ == sraudit.Rotation {
		field = "RotationID"
	}
	parsed, err := validate.ParseManyUUID(field, ids, 50)
	if err != nil {
		return err
	}
	slices.SortFunc(parsed, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	parsed = slices.Compact(parsed)
	defer func() { err = a.srCaptureError(err) }()
	if typ == sraudit.Rotation {
		if _, err = a.tx.ExecContext(ctx, `LOCK rotation_participants, rotation_state IN EXCLUSIVE MODE`); err != nil {
			return err
		}
	}
	table := srRootTable(typ)
	q := `SELECT id FROM ` + table + ` WHERE id=ANY($1::uuid[])`
	args := []any{pq.Array(parsed)}
	if scope != nil {
		q += ` AND organization_id=$2`
		args = append(args, *scope)
	}
	roots, err := lockDeleteCascadeIDs(ctx, a.tx, q+` ORDER BY id FOR UPDATE`, args...)
	if err != nil {
		return err
	}
	if scope != nil && len(roots) != len(parsed) {
		return sql.ErrNoRows
	}
	// A new statement is required after waiting for any root lock.
	rows, err := a.tx.QueryContext(ctx, `SELECT id,organization_id FROM `+table+` WHERE id=ANY($1::uuid[]) ORDER BY id`, pq.Array(roots))
	if err != nil {
		return err
	}
	start := len(a.srTargets)
	for rows.Next() {
		e := a.srBase[typ]
		if err = rows.Scan(&e.RootID, &e.TargetOrganizationID); err != nil {
			break
		}
		if scope != nil && e.TargetOrganizationID != *scope {
			err = sraudit.ErrInvalid
			break
		}
		e.EventID, e.TargetOrgResolution = uuid.New(), "known_normal"
		a.srTargets = append(a.srTargets, e)
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return err
	}
	if len(a.srTargets)-start != len(roots) {
		return sraudit.ErrInvalid
	}
	for i := start; i < len(a.srTargets); i++ {
		e := &a.srTargets[i]
		kinds := []string{sraudit.Rule, sraudit.Favorite, sraudit.Action}
		if typ == sraudit.Schedule {
			kinds = append(kinds, sraudit.Override, sraudit.History)
		} else {
			kinds = append(kinds, sraudit.Participant)
		}
		for _, kind := range kinds {
			if err = a.captureSRChildren(ctx, e, kind); err != nil {
				return err
			}
		}
		if typ == sraudit.Schedule {
			err = a.captureSRData(ctx, e)
		} else {
			s := &sraudit.RotationState{}
			err = a.tx.QueryRowContext(ctx, `SELECT id,rotation_participant_id,position,version,shift_start FROM rotation_state WHERE rotation_id=$1`, e.RootID).Scan(&s.ID, &s.ParticipantID, &s.Position, &s.Version, &s.ShiftStart)
			switch err {
			case sql.ErrNoRows:
				err = nil
			case nil:
				e.BeforeState = s
			}
			if err == nil {
				var n int
				err = a.tx.QueryRowContext(ctx, `SELECT participant_count FROM rotations WHERE id=$1`, e.RootID).Scan(&n)
				count := 0
				for _, f := range e.Effects {
					if f.ResourceType == sraudit.Participant {
						count++
					}
				}
				if err == nil && n != count {
					err = sraudit.ErrInvalid
				}
			}
		}
		if err != nil {
			return err
		}
		if err = a.checkSRBudget(); err != nil {
			return err
		}
	}
	return nil
}

type srChildSpec struct {
	table, parent, detail string
	numeric               bool
}

func srChild(typ, root string) srChildSpec {
	switch typ {
	case sraudit.Rule:
		parent := "schedule_id"
		if root == sraudit.Rotation {
			parent = "tgt_rotation_id"
		}
		return srChildSpec{"schedule_rules", parent, `jsonb_build_object('schedule_id',c.schedule_id,'schedule_organization_id',s.organization_id,'target_kind',CASE WHEN c.tgt_user_id IS NOT NULL THEN 'user' ELSE 'rotation' END,'target_id',coalesce(c.tgt_user_id,c.tgt_rotation_id),'start',c.start_time::text,'end',c.end_time::text,'weekdays',concat(c.sunday::int,c.monday::int,c.tuesday::int,c.wednesday::int,c.thursday::int,c.friday::int,c.saturday::int))`, false}
	case sraudit.Override:
		return srChildSpec{"user_overrides", "tgt_schedule_id", `jsonb_build_object('add_user_id',c.add_user_id,'remove_user_id',c.remove_user_id,'start',c.start_time,'end',c.end_time)`, false}
	case sraudit.Favorite:
		return srChildSpec{"user_favorites", "tgt_" + root + "_id", `jsonb_build_object('owner_user_id',c.user_id,'owner_org_resolution','unknown')`, true}
	case sraudit.Participant:
		return srChildSpec{"rotation_participants", "rotation_id", `jsonb_build_object('user_id',c.user_id,'position',c.position)`, false}
	case sraudit.Action:
		return srChildSpec{"escalation_policy_actions", root + "_id", `jsonb_build_object('policy_id',p.id,'policy_organization_id',p.organization_id,'step_id',s.id)`, false}
	case sraudit.History:
		return srChildSpec{"schedule_on_call_users", "schedule_id", `jsonb_build_object('user_id',c.user_id,'start',c.start_time,'end',c.end_time)`, true}
	default:
		panic("invalid SR effect type")
	}
}

func (a *deleteAllAttempt) srUnits() int {
	n := 0
	for _, e := range a.srTargets {
		n += e.Units()
	}
	return n
}
func (a *deleteAllAttempt) checkSRBudget() error {
	n, size := 0, 0
	for _, e := range a.srTargets {
		n += e.Units()
		size += e.JSONBytes()
	}
	if n > sraudit.MaxEffects || size > sraudit.MaxJSONBytes {
		return sraudit.ErrCapacity
	}
	return nil
}

func (a *deleteAllAttempt) captureSRChildren(ctx context.Context, e *sraudit.Event, kind string) error {
	spec := srChild(kind, e.RootType)
	ids, err := lockDeleteCascadeIDs(ctx, a.tx, `SELECT id::text FROM `+spec.table+` WHERE `+spec.parent+`=$1 ORDER BY id LIMIT $2 FOR UPDATE`, e.RootID, sraudit.MaxEffects-a.srUnits()+1)
	if err != nil {
		return err
	}
	if a.srUnits()+len(ids) > sraudit.MaxEffects {
		return sraudit.ErrCapacity
	}
	idCast := "uuid"
	if spec.numeric {
		idCast = "bigint"
	}
	// Lock the current parent in a separate statement, then read its values in a
	// third statement. A joined locking snapshot is insufficient after a wait.
	switch kind {
	case sraudit.Rule:
		_, err = lockDeleteCascadeIDs(ctx, a.tx, `SELECT id FROM schedules WHERE id IN (SELECT schedule_id FROM schedule_rules WHERE id=ANY($1::uuid[]) AND `+spec.parent+`=$2) ORDER BY id FOR SHARE`, pq.Array(ids), e.RootID)
	case sraudit.Action:
		_, err = lockDeleteCascadeIDs(ctx, a.tx, `SELECT id FROM escalation_policy_steps WHERE id IN (SELECT escalation_policy_step_id FROM escalation_policy_actions WHERE id=ANY($1::uuid[]) AND `+spec.parent+`=$2) ORDER BY id FOR SHARE`, pq.Array(ids), e.RootID)
		if err == nil {
			_, err = lockDeleteCascadeIDs(ctx, a.tx, `SELECT id FROM escalation_policies WHERE id IN (SELECT s.escalation_policy_id FROM escalation_policy_steps s JOIN escalation_policy_actions c ON c.escalation_policy_step_id=s.id WHERE c.id=ANY($1::uuid[]) AND c.`+spec.parent+`=$2) ORDER BY id FOR SHARE`, pq.Array(ids), e.RootID)
		}
	}
	if err != nil {
		return err
	}
	q := `SELECT c.id,` + spec.detail + ` FROM ` + spec.table + ` c`
	if kind == sraudit.Rule {
		q += ` JOIN schedules s ON s.id=c.schedule_id`
	}
	if kind == sraudit.Action {
		q += ` JOIN escalation_policy_steps s ON s.id=c.escalation_policy_step_id JOIN escalation_policies p ON p.id=s.escalation_policy_id`
	}
	q += ` WHERE c.id=ANY($1::` + idCast + `[]) AND c.` + spec.parent + `=$2 ORDER BY c.id`
	rows, err := a.tx.QueryContext(ctx, q, pq.Array(ids), e.RootID)
	if err != nil {
		return err
	}
	var captured []sraudit.Effect
	for rows.Next() {
		f := sraudit.Effect{EffectID: uuid.New(), ResourceType: kind, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID, Relation: sraudit.Relation(e.RootType, kind), Change: "deleted", Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: e.RootType + "_delete"}
		var raw []byte
		if spec.numeric {
			var id int64
			err = rows.Scan(&id, &raw)
			f.ResourceNumericID = &id
		} else {
			var id uuid.UUID
			err = rows.Scan(&id, &raw)
			f.ResourceUUID = &id
		}
		if err != nil {
			break
		}
		var dest any
		switch kind {
		case sraudit.Rule:
			f.Rule = &sraudit.RuleDetail{}
			dest = f.Rule
		case sraudit.Override:
			f.Override = &sraudit.OverrideDetail{}
			dest = f.Override
		case sraudit.Favorite:
			f.Favorite = &sraudit.FavoriteDetail{}
			dest = f.Favorite
			f.Change = "relationship_removed"
		case sraudit.Participant:
			f.Participant = &sraudit.ParticipantDetail{}
			dest = f.Participant
			f.Change = "relationship_removed"
		case sraudit.Action:
			f.Action = &sraudit.ActionDetail{}
			dest = f.Action
		case sraudit.History:
			f.History = &sraudit.HistoryDetail{}
			dest = f.History
		}
		if json.Unmarshal(raw, dest) != nil {
			err = sraudit.ErrInvalid
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
	var count int
	if err = a.tx.QueryRowContext(ctx, `SELECT count(*) FROM `+spec.table+` WHERE `+spec.parent+`=$1`, e.RootID).Scan(&count); err != nil {
		return err
	}
	if count != len(captured) {
		return sraudit.ErrInvalid
	}
	ownerIDs := []uuid.UUID{}
	for _, f := range captured {
		if f.Favorite != nil {
			ownerIDs = append(ownerIDs, f.Favorite.OwnerUserID)
		}
	}
	slices.SortFunc(ownerIDs, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	owners := map[uuid.UUID]executioncontext.CMNROrganizationSnapshot{}
	for _, id := range slices.Compact(ownerIDs) {
		o, err := executioncontext.SnapshotCMNROrganization(ctx, a.tx, id)
		if err != nil {
			return err
		}
		owners[id] = o
	}
	for _, f := range captured {
		if f.Favorite != nil {
			o := owners[f.Favorite.OwnerUserID]
			f.Favorite.OwnerOrgResolution = o.Resolution
			if o.ID != uuid.Nil {
				id := o.ID
				f.Favorite.OwnerOrganizationID = &id
			}
		}
		e.Effects = append(e.Effects, f)
	}
	return a.checkSRBudget()
}

func (a *deleteAllAttempt) captureSRData(ctx context.Context, e *sraudit.Event) error {
	ids, err := lockDeleteCascadeIDs(ctx, a.tx, `SELECT id::text FROM schedule_data WHERE schedule_id=$1 FOR UPDATE`, e.RootID)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	if len(ids) != 1 {
		return sraudit.ErrInvalid
	}
	var id int64
	var valid bool
	// Bound raw SQL work before materializing the projection. Unknown members
	// never leave PostgreSQL. The raw-envelope gate is conservative by design.
	err = a.tx.QueryRowContext(ctx, `SELECT id,octet_length(data::text)<=$2 AND jsonb_typeof(data)='object' AND (data->'V1' IS NULL OR jsonb_typeof(data->'V1')='object') AND (data#>'{V1,TemporarySchedules}' IS NULL OR jsonb_typeof(data#>'{V1,TemporarySchedules}') IN ('array','null')) AND (data#>'{V1,OnCallNotificationRules}' IS NULL OR jsonb_typeof(data#>'{V1,OnCallNotificationRules}') IN ('array','null')) FROM schedule_data WHERE schedule_id=$1`, e.RootID, sraudit.MaxJSONBytes).Scan(&id, &valid)
	if err != nil {
		return err
	}
	if !valid {
		return sraudit.ErrInvalid
	}
	var units int
	err = a.tx.QueryRowContext(ctx, `SELECT coalesce(jsonb_array_length(nullif(data#>'{V1,TemporarySchedules}','null')),0)+coalesce(jsonb_array_length(nullif(data#>'{V1,OnCallNotificationRules}','null')),0)+coalesce((SELECT sum(CASE WHEN jsonb_typeof(t->'Shifts')='array' THEN jsonb_array_length(t->'Shifts') WHEN t->'Shifts' IS NULL OR t->'Shifts'='null' THEN 0 ELSE $2+1 END) FROM jsonb_array_elements(coalesce(nullif(data#>'{V1,TemporarySchedules}','null'),'[]')) t),0) FROM schedule_data WHERE schedule_id=$1`, e.RootID, sraudit.MaxEffects).Scan(&units)
	if err != nil {
		return err
	}
	if units+a.srUnits() > sraudit.MaxEffects {
		return sraudit.ErrCapacity
	}
	var raw []byte
	err = a.tx.QueryRowContext(ctx, `SELECT jsonb_build_object('TemporarySchedules',coalesce((SELECT jsonb_agg(jsonb_build_object('Start',t->'Start','End',t->'End','Shifts',coalesce((SELECT jsonb_agg(jsonb_build_object('Start',s->'Start','End',s->'End','UserID',s->'UserID') ORDER BY sn) FROM jsonb_array_elements(coalesce(nullif(t->'Shifts','null'),'[]')) WITH ORDINALITY sh(s,sn)),'[]')) ORDER BY tn) FROM jsonb_array_elements(coalesce(nullif(data#>'{V1,TemporarySchedules}','null'),'[]')) WITH ORDINALITY ts(t,tn)),'[]'),'OnCallNotificationRules',coalesce((SELECT jsonb_agg(jsonb_build_object('ID',r->'ID','ChannelID',r->'ChannelID','Time',r->'Time','WeekdayFilter',r->'WeekdayFilter') ORDER BY rn) FROM jsonb_array_elements(coalesce(nullif(data#>'{V1,OnCallNotificationRules}','null'),'[]')) WITH ORDINALITY nr(r,rn)),'[]')) FROM schedule_data WHERE schedule_id=$1`, e.RootID).Scan(&raw)
	if err != nil {
		return err
	}
	effects, err := sraudit.ProjectData(*e, id, raw, sraudit.MaxEffects-a.srUnits())
	if err != nil {
		return err
	}
	if len(effects) != units {
		return sraudit.ErrInvalid
	}
	e.Effects = append(e.Effects, effects...)
	return a.checkSRBudget()
}

func (a *deleteAllAttempt) witnessSR(ctx context.Context, typ string, receipts []sraudit.Receipt) (err error) {
	defer func() { err = a.srCaptureError(err) }()
	targets := []sraudit.Event{}
	for _, e := range a.srTargets {
		if e.RootType == typ {
			targets = append(targets, e)
		}
	}
	if err = validateSRReceipts(targets, receipts); err != nil {
		return err
	}
	for _, e := range targets {
		var exists bool
		if err = a.tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM `+srRootTable(typ)+` WHERE id=$1)`, e.RootID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return sraudit.ErrInvalid
		}
		for _, f := range e.Effects {
			table := "schedule_data"
			var id any
			if f.Fragment != nil {
				id = f.Fragment.EnvelopeID
			} else {
				table = srChild(f.ResourceType, typ).table
				if f.ResourceUUID != nil {
					id = *f.ResourceUUID
				} else {
					id = *f.ResourceNumericID
				}
			}
			if err = a.tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM `+table+` WHERE id=$1)`, id).Scan(&exists); err != nil {
				return err
			}
			if exists {
				return sraudit.ErrInvalid
			}
		}
		if typ == sraudit.Rotation {
			if err = a.tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM rotation_state WHERE rotation_id=$1)`, e.RootID).Scan(&exists); err != nil {
				return err
			}
			if exists {
				return sraudit.ErrInvalid
			}
		}
		e.RecordKind, e.Outcome, e.Reason = "success_witness", "committed", "deleted"
		e.Provenance, e.DeletionMechanism, e.Cause = "EXPLICIT", "explicit_sql", "explicit_target"
		a.srSuccesses = append(a.srSuccesses, e.Canonical())
	}
	return sraudit.ValidateBatch(a.srSuccesses)
}

func (a *deleteAllAttempt) appendSR(ctx context.Context) error {
	if !a.plan.hasSchedule && !a.plan.hasRotation {
		return nil
	}
	if len(a.srSuccesses) != len(a.srTargets) {
		return sraudit.ErrInvalid
	}
	targets := map[string]uuid.UUID{}
	for _, e := range a.srTargets {
		targets[e.RootType+":"+e.RootID.String()] = e.TargetOrganizationID
	}
	for _, e := range a.srSuccesses {
		org, ok := targets[e.RootType+":"+e.RootID.String()]
		if !ok || org != e.TargetOrganizationID {
			return sraudit.ErrInvalid
		}
	}
	if err := sraudit.ValidateBatch(a.srSuccesses); err != nil {
		return err
	}
	for _, e := range a.srSuccesses {
		if err := sraudit.Append(ctx, a.tx, e); err != nil {
			return err
		}
	}
	var roots, units, size int
	if err := a.tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(jsonb_array_length(effects)+CASE WHEN before_state='null' THEN 0 ELSE 1 END),0),coalesce(sum(octet_length(effects::text)+CASE WHEN before_state='null' THEN 0 ELSE octet_length(before_state::text) END),0) FROM schedule_rotation_delete_audit_events WHERE attempt_id=$1 AND execution_id=$2 AND record_kind='success_witness'`, a.event.AttemptID, a.event.ExecutionID).Scan(&roots, &units, &size); err != nil {
		return err
	}
	if roots != len(a.srSuccesses) || units != a.srUnits() {
		return sraudit.ErrInvalid
	}
	if units > sraudit.MaxEffects || size > sraudit.MaxJSONBytes {
		return sraudit.ErrCapacity
	}
	return nil
}
func (a *deleteAllAttempt) srFailureEvents(outcome, reason string) []sraudit.Event {
	var events []sraudit.Event
	for _, typ := range []string{sraudit.Rotation, sraudit.Schedule} {
		base, ok := a.srBase[typ]
		if !ok {
			continue
		}
		found := false
		for _, e := range a.srTargets {
			if e.RootType == typ {
				events = append(events, e)
				found = true
			}
		}
		if !found {
			events = append(events, base)
		}
	}
	for i := range events {
		e := &events[i]
		e.EventID, e.RecordKind, e.Outcome, e.Reason, e.OccurredAt = uuid.New(), "attempt_observation", outcome, reason, time.Now()
		e.Provenance, e.DeletionMechanism, e.Cause = "", "", ""
		e.Effects, e.BeforeState = nil, nil
	}
	return events
}

func validateSRReceipts(targets []sraudit.Event, receipts []sraudit.Receipt) error {
	if len(receipts) != len(targets) || len(receipts) > 50 {
		return sraudit.ErrInvalid
	}
	seen := map[uuid.UUID]bool{}
	for _, r := range receipts {
		found := false
		for _, e := range targets {
			if e.RootID == r.ID && e.TargetOrganizationID == r.OrganizationID {
				found = true
			}
		}
		if !found || seen[r.ID] {
			return sraudit.ErrInvalid
		}
		seen[r.ID] = true
	}

	return nil
}
