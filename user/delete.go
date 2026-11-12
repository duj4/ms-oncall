package user

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/target/goalert/permission"
	audit "github.com/target/goalert/user/deleteaudit"
	"github.com/target/goalert/validation/validate"
)

// DeleteManyForAuditTx preserves the legacy deletion order and Rotation state
// machine. The caller alone owns transaction finalization and retries.
func (s *Store) DeleteManyForAuditTx(ctx context.Context, tx *sql.Tx, ids []string, base audit.Event, intents []audit.ExplicitIntent) (result audit.DeleteResult, err error) {
	if err = permission.LimitCheckAny(ctx, permission.System, permission.Admin); err != nil {
		return result, err
	}
	if len(ids) == 0 {
		return result, nil
	}
	if err = validate.Range("Count", len(ids), 1, 100); err != nil {
		return result, err
	}
	if tx == nil {
		return result, audit.ErrUnavailable
	}
	if len(intents) > 100 {
		return result, audit.ErrInvalid
	}
	var budget audit.Budget
	// Bounded root descriptors, receipts, explicit witnesses and their copies.
	if err = budget.Reserve(600, 2*audit.MaxHeaderBytes+100*2048); err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TEMP TABLE sd8_user_delete_witness (
 root_ordinal integer NOT NULL, resource_type text NOT NULL, resource_key text NOT NULL,
 original_ordinal bigint, before_value jsonb NOT NULL, after_value jsonb NOT NULL DEFAULT 'null',
 organization_id uuid, org_resolution text NOT NULL, parent_kind text, parent_id uuid, parent_version text,
 emit boolean NOT NULL DEFAULT true, effect_id uuid NOT NULL DEFAULT gen_random_uuid(), payload jsonb,
 CHECK(octet_length(before_value::text)+octet_length(after_value::text)<=4096),
 CHECK(payload IS NULL OR octet_length(payload::text)<=4096),
 PRIMARY KEY(root_ordinal,resource_type,resource_key)
 ) ON COMMIT DROP`); err != nil {
		return result, err
	}
	// PostgreSQL orders canonical UUID identities, including noncanonical
	// textual forms accepted by the legacy Store. Execution keeps raw input order.
	rows, lockErr := tx.QueryContext(ctx, `SELECT id FROM users WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE`, pq.Array(ids))
	if lockErr != nil {
		return result, lockErr
	}
	for rows.Next() {
		var actual uuid.UUID
		if err = rows.Scan(&actual); err != nil {
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr := rows.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return result, err
	}

	for ordinal, id := range ids {
		var b audit.Before
		var uid uuid.UUID
		err = tx.QueryRowContext(ctx, `SELECT id,role::text,xmin::text::bigint FROM users WHERE id=$1 FOR UPDATE`, id).Scan(&uid, &b.UserRole, &b.RowVersion)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return result, err
		}
		b.Version, b.UserID = 1, uid
		b.OrganizationRole = "unknown"
		var assignmentVersion uint32
		err = tx.QueryRowContext(ctx, `SELECT xmin::text::bigint,organization_role::text FROM user_organization_assignments WHERE user_id=$1 FOR SHARE`, uid).Scan(&assignmentVersion, &b.OrganizationRole)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return result, err
		}
		if err == nil {
			b.AssignmentPresent = true
			b.AssignmentRowVersion = &assignmentVersion
		}
		org, readErr := audit.SnapshotOrganization(ctx, tx, uid)
		if readErr != nil {
			return result, readErr
		}
		b.TargetOrganizationID, b.TargetOrgResolution = audit.ID(org.ID), org.Resolution
		e := base
		e.EventID = uuid.New()
		e.RootID = &uid
		e.RootOrdinal = &ordinal
		e.BeforeContext = &b
		e.TargetOrganizationID, e.TargetOrgResolution = b.TargetOrganizationID, b.TargetOrgResolution
		e.RecordKind, e.Outcome, e.Reason = "success_witness", "committed", "deleted"
		e.Provenance, e.DeletionMechanism, e.Cause = "EXPLICIT", "explicit_sql", "explicit_target"
		e.Manifest = map[string]int64{}
		e.EffectCount, e.EffectJSONBytes = 0, 0
		e.RelatedExplicitEvents = nil
		target := e
		target.BeforeContext = nil
		target.Manifest = nil
		target.RecordKind, target.Outcome, target.Reason = "", "", ""
		target.Provenance, target.DeletionMechanism, target.Cause = "", "", ""
		result.Targets = append(result.Targets, target)
		c := userDeleteCapture{ctx: ctx, tx: tx, ordinal: ordinal, user: uid, event: e.EventID, budget: &budget, rootOrg: org}
		if err = c.captureChildren(); err != nil {
			return result, err
		}
		witnesses, captureErr := c.explicitWitnesses(intents, e)
		if captureErr != nil {
			return result, captureErr
		}
		if err = c.removeRotations(); err != nil {
			return result, err
		}
		r := audit.Receipt{Event: e, Witnesses: witnesses}
		err = tx.QueryRowContext(ctx, `DELETE FROM users WHERE id=$1 RETURNING id,role::text,xmin::text::bigint`, uid).Scan(&r.DeletedUserID, &r.DeletedRole, &r.DeletedRowVersion)
		if err != nil {
			return result, err
		}
		if r.DeletedUserID != uid || r.DeletedRole != b.UserRole || r.DeletedRowVersion != b.RowVersion {
			return result, audit.ErrInvalid
		}
		if err = c.verifyChildren(); err != nil {
			return result, err
		}
		for i := range r.Witnesses {
			r.Witnesses[i].Verified = true
			w := r.Witnesses[i]
			r.Event.RelatedExplicitEvents = append(r.Event.RelatedExplicitEvents, audit.RelatedExplicitEvent{EventID: w.EventID, ResourceType: w.ResourceType, ResourceID: w.ResourceID})
		}
		if err = c.finalizeEffects(&r.Event, r.Witnesses); err != nil {
			return result, err
		}
		r.CaptureHighUnits, r.ActiveJSONHighBytes = budget.HighUnits, budget.HighBytes
		r.EffectPages = (r.Event.EffectCount + audit.PageSize - 1) / audit.PageSize
		r.Event = r.Event.Canonical()
		if err = r.Validate(); err != nil {
			return result, err
		}
		result.Receipts = append(result.Receipts, r)
	}
	return result, nil
}

type userDeleteCapture struct {
	ctx         context.Context
	tx          *sql.Tx
	ordinal     int
	user, event uuid.UUID
	budget      *audit.Budget
	rootOrg     audit.OrganizationSnapshot
}

type userDeleteChild struct {
	typ, table, key, predicate, owner, parentKind, parent string
	fields                                                map[string]string
}

func (c *userDeleteCapture) children() []userDeleteChild {
	cm := `SELECT resource_key::uuid FROM pg_temp.sd8_user_delete_witness WHERE root_ordinal=$2 AND resource_type='contact_method'`
	children := []userDeleteChild{
		{typ: "contact_method", table: "user_contact_methods", key: "id", predicate: "b.user_id=$1", owner: "b.user_id", fields: map[string]string{"id": "b.id", "user_id": "b.user_id", "type": "b.type", "disabled": "b.disabled", "pending": "b.pending", "private": "b.private"}},
		{typ: "notification_rule", table: "user_notification_rules", key: "id", predicate: "b.user_id=$1 OR b.contact_method_id IN (" + cm + ")", owner: "b.user_id", fields: map[string]string{"id": "b.id", "user_id": "b.user_id", "parent_cm_id": "b.contact_method_id", "delay_minutes": "b.delay_minutes"}},
		{typ: "schedule_rule", table: "schedule_rules", key: "id", predicate: "b.tgt_user_id=$1", parentKind: "schedule", parent: "b.schedule_id", fields: map[string]string{"id": "b.id", "schedule_id": "b.schedule_id", "target_user_id": "b.tgt_user_id", "start": "b.start_time", "end": "b.end_time", "weekdays": "(b.sunday::int+2*b.monday::int+4*b.tuesday::int+8*b.wednesday::int+16*b.thursday::int+32*b.friday::int+64*b.saturday::int)", "is_active": "b.is_active"}},
		{typ: "user_override", table: "user_overrides", key: "id", predicate: "b.add_user_id=$1 OR b.remove_user_id=$1", parentKind: "schedule", parent: "b.tgt_schedule_id", fields: map[string]string{"id": "b.id", "schedule_id": "b.tgt_schedule_id", "add_user_id": "b.add_user_id", "remove_user_id": "b.remove_user_id", "start": "b.start_time", "end": "b.end_time"}},
		{typ: "user_favorite", table: "user_favorites", key: "id", predicate: "b.user_id=$1 OR b.tgt_user_id=$1", owner: "b.user_id", fields: map[string]string{"id": "b.id", "user_id": "b.user_id", "target_user_id": "b.tgt_user_id", "target_service_id": "b.tgt_service_id", "target_schedule_id": "b.tgt_schedule_id", "target_rotation_id": "b.tgt_rotation_id", "target_escalation_policy_id": "b.tgt_escalation_policy_id"}},
		{typ: "escalation_policy_action", table: "escalation_policy_actions", key: "id", predicate: "b.user_id=$1", parentKind: "step", parent: "b.escalation_policy_step_id", fields: map[string]string{"id": "b.id", "step_id": "b.escalation_policy_step_id", "policy_id": "(SELECT escalation_policy_id FROM escalation_policy_steps WHERE id=b.escalation_policy_step_id)", "user_id": "b.user_id"}},
		{typ: "schedule_on_call_history", table: "schedule_on_call_users", key: "id", predicate: "b.user_id=$1", parentKind: "schedule", parent: "b.schedule_id", fields: map[string]string{"id": "b.id", "schedule_id": "b.schedule_id", "user_id": "b.user_id", "start": "b.start_time", "end": "b.end_time"}},
		{typ: "ep_step_on_call_history", table: "ep_step_on_call_users", key: "id", predicate: "b.user_id=$1", parentKind: "step", parent: "b.ep_step_id", fields: map[string]string{"id": "b.id", "step_id": "b.ep_step_id", "policy_id": "(SELECT escalation_policy_id FROM escalation_policy_steps WHERE id=b.ep_step_id)", "user_id": "b.user_id", "start": "b.start_time", "end": "b.end_time"}},
		{typ: "user_organization_assignment", table: "user_organization_assignments", key: "user_id", predicate: "b.user_id=$1", owner: "b.user_id", fields: map[string]string{"user_id": "b.user_id", "organization_id": "b.effective_organization_id", "classification": "b.effective_organization_classification", "organization_role": "b.organization_role"}},
		{typ: "auth_subject", table: "auth_subjects", key: "id", predicate: "b.user_id=$1 OR b.cm_id IN (" + cm + ")", owner: "b.user_id", fields: map[string]string{"id": "b.id", "user_id": "b.user_id", "cm_id": "b.cm_id"}},
		{typ: "user_session", table: "auth_user_sessions", key: "id", predicate: "b.user_id=$1", owner: "b.user_id", fields: map[string]string{"id": "b.id", "user_id": "b.user_id"}},
		{typ: "basic_auth_link", table: "auth_basic_users", key: "user_id", predicate: "b.user_id=$1", owner: "b.user_id", fields: map[string]string{"id": "b.id", "user_id": "b.user_id"}},
		{typ: "user_status_contact_setting", table: "users", key: "id", predicate: "b.id<>$1 AND b.alert_status_log_contact_method_id IN (" + cm + ")", owner: "b.id", fields: map[string]string{"user_id": "b.id", "contact_method_id": "b.alert_status_log_contact_method_id"}},
	}
	for i := range children {
		if children[i].typ == "schedule_rule" {
			continue
		}
		for _, key := range []string{"start", "end"} {
			if expression, ok := children[i].fields[key]; ok {
				children[i].fields[key] = safeTimestampSQL(expression)
			}
		}
	}
	return children

}

func projectionSQL(fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	args := make([]string, 0, 2*len(keys)+2)
	for _, k := range keys {
		args = append(args, "'"+k+"'", fields[k])
	}
	args = append(args, "'row_version'", "b.xmin::text::bigint")
	return "jsonb_build_object(" + strings.Join(args, ",") + ")"
}

func (c *userDeleteCapture) captureChildren() error {
	for _, d := range c.children() {
		last := ""
		for {
			// Reserve both page identities and re-read snapshots before allocating.
			if err := c.budget.Reserve(4*audit.PageSize, 2*audit.PageSize*audit.MaxLeafBytes); err != nil {
				return err
			}
			query := `SELECT b.` + d.key + `::text FROM ` + d.table + ` b WHERE (` + d.predicate + `) AND b.` + d.key + `::text>$3 AND $2>=0 ORDER BY b.` + d.key + `::text LIMIT 256 FOR UPDATE OF b`
			rows, err := c.tx.QueryContext(c.ctx, query, c.user, c.ordinal, last)
			if err != nil {
				return err
			}
			keys := make([]string, 0, audit.PageSize)
			for rows.Next() {
				var key string
				if err = rows.Scan(&key); err != nil {
					break
				}
				keys = append(keys, key)
			}
			if err == nil {
				err = rows.Err()
			}
			closeErr := rows.Close()
			if err == nil {
				err = closeErr
			}
			if err != nil {
				return err
			}
			for _, key := range keys {
				owner, parent := "NULL::uuid", "NULL::uuid"
				if d.owner != "" {
					owner = d.owner
				}
				if d.parent != "" {
					parent = d.parent
				}
				var before []byte
				var oid, pid uuid.NullUUID
				err = c.tx.QueryRowContext(c.ctx, `SELECT `+projectionSQL(d.fields)+`,`+owner+`,`+parent+` FROM `+d.table+` b WHERE b.`+d.key+`::text=$1`, key).Scan(&before, &oid, &pid)
				if err != nil {
					return err
				}
				if err = audit.ValidateSnapshot(d.typ, key, before); err != nil {
					return err
				}
				org := c.rootOrg
				var parentVersion sql.NullString
				if oid.Valid && oid.UUID != c.user {
					org, err = audit.SnapshotOrganization(c.ctx, c.tx, oid.UUID)
					if err != nil {
						return err
					}
				}
				if pid.Valid {
					org, parentVersion, err = c.parentSnapshot(d.parentKind, pid.UUID, d.typ != "user_override")
					if err != nil {
						return err
					}
				}
				inserted, insertErr := c.tx.ExecContext(c.ctx, `INSERT INTO pg_temp.sd8_user_delete_witness(root_ordinal,resource_type,resource_key,before_value,organization_id,org_resolution,parent_kind,parent_id,parent_version) VALUES($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9)`, c.ordinal, d.typ, key, string(before), audit.ID(org.ID), org.Resolution, d.parentKind, pid, parentVersion)
				if insertErr != nil {
					return insertErr
				}
				n, insertErr := inserted.RowsAffected()
				if insertErr != nil {
					return insertErr
				}
				if n != 1 {
					return audit.ErrInvalid
				}
			}
			if err = c.budget.Release(4*audit.PageSize, 2*audit.PageSize*audit.MaxLeafBytes); err != nil {
				return err
			}
			if len(keys) == 0 {
				break
			}
			last = keys[len(keys)-1]
		}
		// All qualifying children are now locked. A fresh whole-set count binds
		// the keyset inventory to the real FK closure, including a missing page.
		var actual, captured int64
		err := c.tx.QueryRowContext(c.ctx, `SELECT (SELECT count(*) FROM `+d.table+` b WHERE (`+d.predicate+`) AND $2>=0),(SELECT count(*) FROM pg_temp.sd8_user_delete_witness WHERE root_ordinal=$2 AND resource_type=$3)`, c.user, c.ordinal, d.typ).Scan(&actual, &captured)
		if err != nil {
			return err
		}
		if actual != captured {
			return audit.ErrInvalid
		}
	}
	return nil
}

func (c *userDeleteCapture) parentSnapshot(kind string, id uuid.UUID, lock bool) (audit.OrganizationSnapshot, sql.NullString, error) {
	org := audit.OrganizationSnapshot{Resolution: "known_normal"}
	var version sql.NullString
	var query string
	switch kind {
	case "schedule":
		query = `SELECT organization_id,xmin::text FROM schedules WHERE id=$1`
	case "rotation":
		query = `SELECT organization_id,xmin::text FROM rotations WHERE id=$1`
	case "step":
		query = `SELECT e.organization_id,s.xmin::text||'/'||e.xmin::text FROM escalation_policy_steps s JOIN escalation_policies e ON e.id=s.escalation_policy_id WHERE s.id=$1`
	default:
		return org, version, audit.ErrInvalid
	}
	if lock {
		query += " FOR SHARE"
	}
	err := c.tx.QueryRowContext(c.ctx, query, id).Scan(&org.ID, &version)
	if err != nil {
		return org, version, err
	}
	if org.ID.String() == "296e2656-7221-53fe-bd0a-832d24ccfd03" {
		org.Resolution = "known_default"
	}
	return org, version, nil
}

func (c *userDeleteCapture) verifyChildren() error {
	for _, d := range c.children() {
		var bad bool
		if d.typ == "user_status_contact_setting" {
			err := c.tx.QueryRowContext(c.ctx, `SELECT EXISTS(SELECT FROM pg_temp.sd8_user_delete_witness w LEFT JOIN users u ON u.id=w.resource_key::uuid WHERE w.root_ordinal=$1 AND w.resource_type=$2 AND (u.id IS NULL OR u.alert_status_log_contact_method_id IS NOT NULL))`, c.ordinal, d.typ).Scan(&bad)
			if err != nil {
				return err
			}
			if !bad {
				_, err = c.tx.ExecContext(c.ctx, `UPDATE pg_temp.sd8_user_delete_witness w SET after_value=jsonb_build_object('user_id',u.id,'contact_method_id',u.alert_status_log_contact_method_id,'row_version',u.xmin::text::bigint) FROM users u WHERE w.root_ordinal=$1 AND w.resource_type=$2 AND u.id=w.resource_key::uuid`, c.ordinal, d.typ)
				if err != nil {
					return err
				}
			}
		} else {
			query := `SELECT EXISTS(SELECT FROM ` + d.table + ` b WHERE (` + d.predicate + `) AND $2>=0) OR EXISTS(SELECT FROM ` + d.table + ` b JOIN pg_temp.sd8_user_delete_witness w ON b.` + d.key + `::text=w.resource_key WHERE w.root_ordinal=$2 AND w.resource_type=$3)`
			if err := c.tx.QueryRowContext(c.ctx, query, c.user, c.ordinal, d.typ).Scan(&bad); err != nil {
				return err
			}
		}
		if bad {
			return audit.ErrInvalid
		}
	}
	// UO attribution uses the SD7 parent witness pattern, with a fresh post-check.
	var last string
	for {
		var key, kind string
		var parent uuid.UUID
		var version string
		var org uuid.UUID
		err := c.tx.QueryRowContext(c.ctx, `SELECT resource_key,parent_kind,parent_id,parent_version,organization_id FROM pg_temp.sd8_user_delete_witness WHERE root_ordinal=$1 AND resource_type='user_override' AND resource_key>$2 ORDER BY resource_key LIMIT 1`, c.ordinal, last).Scan(&key, &kind, &parent, &version, &org)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return err
		}
		actual, v, err := c.parentSnapshot(kind, parent, false)
		if err != nil {
			return err
		}
		if actual.ID != org || !v.Valid || v.String != version {
			return audit.ErrInvalid
		}
		last = key
	}
	var remaining bool
	if err := c.tx.QueryRowContext(c.ctx, `SELECT EXISTS(SELECT FROM users WHERE id=$1) OR EXISTS(SELECT FROM rotation_participants WHERE user_id=$1)`, c.user).Scan(&remaining); err != nil {
		return err
	}
	if remaining {
		return audit.ErrInvalid
	}
	return nil
}

func (c *userDeleteCapture) explicitWitnesses(intents []audit.ExplicitIntent, e audit.Event) ([]audit.ExplicitWitness, error) {
	var result []audit.ExplicitWitness
	for _, intent := range intents {
		if intent.ResourceType != "contact_method" && intent.ResourceType != "notification_rule" {
			return nil, audit.ErrInvalid
		}
		var raw []byte
		var org uuid.NullUUID
		var resolution string
		err := c.tx.QueryRowContext(c.ctx, `SELECT before_value,organization_id,org_resolution FROM pg_temp.sd8_user_delete_witness WHERE root_ordinal=$1 AND resource_type=$2 AND resource_key=$3`, c.ordinal, intent.ResourceType, intent.ID.String()).Scan(&raw, &org, &resolution)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var b struct {
			UserID     uuid.UUID  `json:"user_id"`
			ParentCMID *uuid.UUID `json:"parent_cm_id"`
			RowVersion uint32     `json:"row_version"`
		}
		if err = json.Unmarshal(raw, &b); err != nil {
			return nil, audit.ErrInvalid
		}
		w := audit.ExplicitWitness{EventID: uuid.New(), ResourceType: intent.ResourceType, ResourceID: intent.ID, IntentOrdinal: intent.Ordinal, OwnerID: b.UserID, ParentCMID: b.ParentCMID, TargetOrgResolution: resolution, RowVersion: b.RowVersion, CauseUserID: c.user, CauseEventID: c.event, RequestID: e.RequestID, ExecutionID: e.ExecutionID, AttemptID: e.AttemptID, OwnerFK: b.UserID == c.user}
		if org.Valid {
			w.TargetOrganizationID = audit.ID(org.UUID)
		}
		if b.ParentCMID != nil {
			err = c.tx.QueryRowContext(c.ctx, `SELECT EXISTS(SELECT FROM pg_temp.sd8_user_delete_witness WHERE root_ordinal=$1 AND resource_type='contact_method' AND resource_key=$2)`, c.ordinal, b.ParentCMID.String()).Scan(&w.ContactMethodFK)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, w)
	}
	return result, nil
}

func (c *userDeleteCapture) finalizeEffects(e *audit.Event, explicit []audit.ExplicitWitness) error {
	for _, w := range explicit {
		if _, err := c.tx.ExecContext(c.ctx, `UPDATE pg_temp.sd8_user_delete_witness SET emit=false WHERE root_ordinal=$1 AND resource_type=$2 AND resource_key=$3`, c.ordinal, w.ResourceType, w.ResourceID.String()); err != nil {
			return err
		}
	}
	var lastType, lastKey string
	for {
		if err := c.budget.Reserve(4*audit.PageSize, 2*audit.PageSize*audit.MaxLeafBytes); err != nil {
			return err
		}
		rows, err := c.tx.QueryContext(c.ctx, `SELECT resource_type,resource_key,effect_id,before_value,after_value,organization_id,org_resolution FROM pg_temp.sd8_user_delete_witness WHERE root_ordinal=$1 AND emit AND (resource_type,resource_key)>($2,$3) ORDER BY resource_type,resource_key LIMIT 256`, c.ordinal, lastType, lastKey)
		if err != nil {
			return err
		}
		page := make([]audit.Effect, 0, audit.PageSize)
		for rows.Next() {
			f := audit.Effect{TransitionSlot: "row", TriggerUserID: c.user}
			var org uuid.NullUUID
			if err = rows.Scan(&f.ResourceType, &f.ResourceKey, &f.EffectID, &f.Before, &f.After, &org, &f.OrgResolution); err != nil {
				break
			}
			if org.Valid {
				f.TargetOrganizationID = audit.ID(org.UUID)
			}
			page = append(page, f)
		}
		if err == nil {
			err = rows.Err()
		}
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		for _, f := range page {
			f.Change, f.Provenance, f.DeletionMechanism = "deleted", "IMPLICIT_FK_CASCADE", "fk_cascade"
			switch f.ResourceType {
			case "user_favorite", "user_organization_assignment":
				f.Change = "relationship_removed"
			case "rotation_participant":
				f.Change, f.Provenance, f.DeletionMechanism = "relationship_reassigned", "IMPLICIT_APPLICATION_UPDATE", "application_update"
				if string(f.After) == "null" {
					f.Change, f.Provenance, f.DeletionMechanism = "relationship_removed", "IMPLICIT_APPLICATION_DELETE", "explicit_sql"
				}
			case "rotation_participant_count", "rotation_state":
				f.Change, f.Provenance, f.DeletionMechanism = "state_updated", "IMPLICIT_TRIGGER_UPDATE", "trigger_update"
				if string(f.After) == "null" {
					f.Change, f.Provenance, f.DeletionMechanism = "deleted", "IMPLICIT_TRIGGER_DELETE", "trigger_delete"
				}
			case "user_status_contact_setting":
				f.Change, f.Provenance, f.DeletionMechanism = "relationship_cleared", "IMPLICIT_FK_SET_NULL", "fk_set_null"
			}
			if err = f.Validate(c.user); err != nil {
				return err
			}
			raw, err := json.Marshal(f)
			if err != nil {
				return audit.ErrInvalid
			}
			var size int64
			err = c.tx.QueryRowContext(c.ctx, `UPDATE pg_temp.sd8_user_delete_witness SET payload=$4::jsonb WHERE root_ordinal=$1 AND resource_type=$2 AND resource_key=$3 RETURNING octet_length(payload::text)`, c.ordinal, f.ResourceType, f.ResourceKey, string(raw)).Scan(&size)
			if err != nil {
				return err
			}
			if size > audit.MaxLeafBytes {
				return audit.ErrCapacity
			}
			if e.EffectCount == int64(^uint64(0)>>1) || e.EffectJSONBytes > int64(^uint64(0)>>1)-size {
				return audit.ErrCapacity
			}
			e.EffectCount++
			e.EffectJSONBytes += size
			e.Manifest[f.ResourceType]++
		}
		if err = c.budget.Release(4*audit.PageSize, 2*audit.PageSize*audit.MaxLeafBytes); err != nil {
			return err
		}
		if len(page) == 0 {
			break
		}
		last := page[len(page)-1]
		lastType, lastKey = last.ResourceType, last.ResourceKey
	}
	return nil
}

// Only the safe projection changes timezone, never the transaction or business
// SQL. Timestamp text retains PostgreSQL extended years, BC and infinities.
func safeTimestampSQL(expression string) string {
	return "CASE WHEN " + expression + " IS NULL THEN NULL WHEN isfinite(" + expression + ") THEN regexp_replace((to_jsonb(" + expression + " AT TIME ZONE 'UTC')#>>'{}'),'( BC)?$','Z\\1') ELSE " + expression + "::text END"
}
