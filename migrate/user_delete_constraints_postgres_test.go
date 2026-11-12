package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	cmnr "github.com/target/goalert/user/cmnrdeleteaudit"
	audit "github.com/target/goalert/user/deleteaudit"
)

func sd8InsertCMNR(ctx context.Context, tx *sql.Tx, e cmnr.Event) error {
	witness, err := json.Marshal(e.UserCauseWitness)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO user_cmnr_delete_audit_events(event_id,request_id,execution_id,attempt_id,record_kind,operation,root_type,root_id,root_owner_user_id,target_organization_id,target_org_resolution,parent_cm_id,provenance,deletion_mechanism,cause_event_id,actor_kind,actor_id,home_organization_id,authority_source,authority_role,organization_role,outcome,reason_code,occurred_at,schema_version,cause_root_type,cause_root_id,user_cause_witness) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28::jsonb)`, e.EventID, e.RequestID, e.ExecutionID, e.AttemptID, e.RecordKind, e.Operation, e.RootType, e.RootID, e.RootOwnerUserID, cmnr.NullableID(e.TargetOrganizationID), e.TargetOrgResolution, cmnr.NullableID(e.ParentCMID), e.Provenance, e.DeletionMechanism, cmnr.NullableID(e.CauseEventID), e.ActorKind, cmnr.NullableID(e.ActorID), cmnr.NullableID(e.HomeOrganizationID), e.AuthoritySource, e.AuthorityRole, e.OrganizationRole, e.Outcome, e.Reason, e.OccurredAt, e.SchemaVersion, e.CauseRootType, cmnr.NullableID(e.CauseRootID), string(witness))
	return err
}

func TestPostgresUserDeleteV1AndCauseConstraints(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, 301)
	legacy := cmnrDBEvent()
	_, err := db.ExecContext(ctx, `INSERT INTO user_cmnr_delete_audit_events(event_id,request_id,execution_id,attempt_id,record_kind,operation,root_type,root_id,root_owner_user_id,target_organization_id,target_org_resolution,provenance,deletion_mechanism,actor_kind,actor_id,home_organization_id,authority_source,authority_role,organization_role,outcome,reason_code,occurred_at) VALUES($1,$2,$3,$4,'success_witness','contact_method.delete','contact_method',$5,$6,$7,'known_normal','EXPLICIT','explicit_sql','human',$6,$7,'current_local_user_organization_at_admission','org_member','ORG_MEMBER','committed','deleted',now())`, legacy.EventID, legacy.RequestID, legacy.ExecutionID, legacy.AttemptID, legacy.RootID, legacy.RootOwnerUserID, legacy.TargetOrganizationID)
	require.NoError(t, err)
	var before, xmin string
	require.NoError(t, db.QueryRow(`SELECT to_jsonb(e)::text,xmin::text FROM user_cmnr_delete_audit_events e WHERE event_id=$1`, legacy.EventID).Scan(&before, &xmin))
	n, err := Up(ctx, uri, "")
	require.NoError(t, err)
	require.Equal(t, 1, n)
	var after, afterXmin string
	require.NoError(t, db.QueryRow(`SELECT (to_jsonb(e)-'cause_root_type'-'cause_root_id'-'user_cause_witness')::text,xmin::text FROM user_cmnr_delete_audit_events e WHERE event_id=$1`, legacy.EventID).Scan(&after, &afterXmin))
	require.JSONEq(t, before, after)
	require.Equal(t, xmin, afterXmin)
	for _, mode := range []string{"valid_cm", "valid_nr", "missing_cause", "wrong_attempt", "wrong_actor", "wrong_owner", "wrong_parent", "wrong_org", "pending_witness", "unrelated_root", "unreferenced", "v1_cause_forbidden"} {
		t.Run(mode, func(t *testing.T) {
			root := sd8SchemaEvent()
			c := cmnr.Event{SchemaVersion: 2, EventID: uuid.New(), RequestID: root.RequestID, ExecutionID: root.ExecutionID, AttemptID: root.AttemptID, RecordKind: "success_witness", Operation: "contact_method.delete", RootType: "contact_method", RootID: uuid.New(), RootOwnerUserID: *root.RootID, TargetOrgResolution: "unknown", Provenance: "EXPLICIT", DeletionMechanism: "fk_cascade", CauseEventID: root.EventID, CauseRootType: "user", CauseRootID: *root.RootID, ActorKind: root.ActorKind, AuthoritySource: root.AuthoritySource, AuthorityRole: root.AuthorityRole, OrganizationRole: root.OrganizationRole, Outcome: "committed", Reason: "deleted", OccurredAt: root.OccurredAt}
			if mode == "valid_nr" || mode == "wrong_parent" {
				c.RootType, c.Operation, c.ParentCMID = "notification_rule", "notification_rule.delete", uuid.New()
			}
			w := audit.ExplicitWitness{EventID: c.EventID, ResourceType: c.RootType, ResourceID: c.RootID, OwnerID: c.RootOwnerUserID, ParentCMID: cmnr.NullableID(c.ParentCMID), TargetOrgResolution: "unknown", RowVersion: 1, CauseUserID: *root.RootID, CauseEventID: root.EventID, RequestID: root.RequestID, ExecutionID: root.ExecutionID, AttemptID: root.AttemptID, OwnerFK: true, Verified: true}
			c.UserCauseWitness = &w
			root.RelatedExplicitEvents = []audit.RelatedExplicitEvent{{EventID: c.EventID, ResourceType: c.RootType, ResourceID: c.RootID}}
			switch mode {
			case "missing_cause":
				c.CauseEventID = uuid.New()
				w.CauseEventID = c.CauseEventID
			case "wrong_attempt":
				c.AttemptID = uuid.New()
				w.AttemptID = c.AttemptID
			case "wrong_actor":
				c.ActorKind = "human"
				c.ActorID = uuid.New()
				c.HomeOrganizationID = uuid.New()
				c.AuthoritySource = "current_local_user_organization_at_admission"
				c.AuthorityRole = "platform_admin"
				c.OrganizationRole = "ORG_MEMBER"
			case "wrong_owner":
				c.RootOwnerUserID = uuid.New()
			case "wrong_parent":
				c.ParentCMID = uuid.New()
			case "wrong_org":
				c.TargetOrganizationID = uuid.New()
				c.TargetOrgResolution = "known_normal"
				w.TargetOrganizationID = audit.ID(c.TargetOrganizationID)
				w.TargetOrgResolution = c.TargetOrgResolution
			case "pending_witness":
				w.Verified = false
			case "unrelated_root":
				c.CauseRootID = uuid.New()
				w.CauseUserID = c.CauseRootID
			case "unreferenced":
				root.RelatedExplicitEvents = nil
			case "v1_cause_forbidden":
				c.SchemaVersion = 1
			}
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			require.NoError(t, audit.Append(ctx, tx, root))
			err = sd8InsertCMNR(ctx, tx, c)
			if err == nil {
				_, err = tx.ExecContext(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
			}
			if strings.HasPrefix(mode, "valid_") {
				require.NoError(t, err)
				require.NoError(t, tx.Commit())
			} else {
				var pg *pgconn.PgError
				require.ErrorAs(t, err, &pg)
				require.True(t, strings.HasPrefix(pg.Code, "23"), pg.Code)
				require.NoError(t, tx.Rollback())
			}
		})
	}
	n, err = Down(ctx, uri, "user-override-delete-audit")
	require.Error(t, err)
	require.Zero(t, n)
	require.NoError(t, VerifyIsLatest(ctx, uri))
	require.NoError(t, db.QueryRow(`SELECT (to_jsonb(e)-'cause_root_type'-'cause_root_id'-'user_cause_witness')::text FROM user_cmnr_delete_audit_events e WHERE event_id=$1`, legacy.EventID).Scan(&after))
	require.JSONEq(t, before, after)
}

func sd8Detail(root audit.Event, id int64) audit.Effect {
	before := json.RawMessage(fmt.Sprintf(`{"id":%d,"schedule_id":%q,"user_id":%q,"start":"2020-01-01T00:00:00Z","end":null,"row_version":1}`, id, uuid.NewString(), root.RootID.String()))
	return audit.Effect{EffectID: uuid.New(), ResourceType: "schedule_on_call_history", ResourceKey: fmt.Sprint(id), TransitionSlot: "row", TriggerUserID: *root.RootID, OrgResolution: "unknown", Change: "deleted", Provenance: "IMPLICIT_FK_CASCADE", DeletionMechanism: "fk_cascade", Before: before, After: json.RawMessage("null")}
}

func TestPostgresUserDeleteDetailCompleteness(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, 302)
	for _, mode := range []string{"zero", "one", "257", "missing", "extra_ordinal", "wrong_declared", "duplicate_ordinal", "duplicate_resource", "wrong_cause", "unknown_key", "wrong_bytes"} {
		t.Run(mode, func(t *testing.T) {
			root := sd8SchemaEvent()
			count := 1
			if mode == "zero" {
				count = 0
			}
			if mode == "257" {
				count = 257
			}
			if mode == "duplicate_resource" || mode == "duplicate_ordinal" {
				count = 2
			}
			rows := make([]string, count)
			effects := make([]audit.Effect, count)
			var total int64
			for i := range rows {
				effects[i] = sd8Detail(root, int64(i+1))
				raw, err := json.Marshal(effects[i])
				require.NoError(t, err)
				rows[i] = string(raw)
				var bytes int64
				require.NoError(t, db.QueryRow(`SELECT octet_length($1::jsonb::text)`, rows[i]).Scan(&bytes))
				total += bytes
			}
			root.EffectCount, root.EffectJSONBytes = int64(count), total
			root.Manifest = map[string]int64{}
			if count > 0 {
				root.Manifest["schedule_on_call_history"] = int64(count)
			}
			if mode == "wrong_bytes" {
				root.EffectJSONBytes++
			}
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			require.NoError(t, audit.Append(ctx, tx, root))
			for i, row := range rows {
				if mode == "missing" {
					continue
				}
				ordinal, declared := int64(i), root.EffectCount
				effect := effects[i]
				switch mode {
				case "extra_ordinal":
					ordinal = root.EffectCount
				case "wrong_declared":
					declared++
				case "duplicate_ordinal":
					ordinal = 0
				case "duplicate_resource":
					effect = effects[0]
				case "wrong_cause":
					effect.TriggerUserID = uuid.New()
				}
				if mode == "wrong_cause" || mode == "duplicate_resource" {
					raw, _ := json.Marshal(effect)
					row = string(raw)
				}
				if mode == "unknown_key" {
					row = strings.TrimSuffix(row, "}") + `,"password_hash":"SYNTHETIC_PRIVATE"}`
				}
				_, err = tx.ExecContext(ctx, `INSERT INTO user_delete_audit_effects(event_id,effect_ordinal,declared_effect_count,effect_id,resource_type,resource_key,transition_slot,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`, root.EventID, ordinal, declared, effect.EffectID, effect.ResourceType, effect.ResourceKey, effect.TransitionSlot, row)
				if err != nil {
					break
				}
			}
			if err == nil {
				_, err = tx.ExecContext(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
			}
			valid := mode == "zero" || mode == "one" || mode == "257"
			if valid {
				require.NoError(t, err)
				require.NoError(t, audit.Append(ctx, tx, root))
				changed := root
				changed.OccurredAt = changed.OccurredAt.Add(time.Second)
				require.ErrorIs(t, audit.Append(ctx, tx, changed), audit.ErrConflict)
				require.NoError(t, tx.Commit())
			} else {
				var pg *pgconn.PgError
				require.ErrorAs(t, err, &pg)
				require.True(t, strings.HasPrefix(pg.Code, "23"), pg.Code)
				require.NoError(t, tx.Rollback())
			}
			var actual int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM user_delete_audit_events WHERE event_id=$1`, root.EventID).Scan(&actual))
			if valid {
				require.Equal(t, 1, actual)
			} else {
				require.Zero(t, actual)
			}
		})
	}
	for _, table := range []string{"user_delete_audit_events", "user_delete_audit_effects"} {
		for _, q := range []string{`UPDATE ` + table + ` SET event_id=event_id WHERE false`, `DELETE FROM ` + table + ` WHERE false`, `TRUNCATE ` + table} {
			_, err := db.ExecContext(ctx, q)
			var pg *pgconn.PgError
			require.ErrorAs(t, err, &pg)
			if table == "user_delete_audit_events" && strings.HasPrefix(q, "TRUNCATE ") {
				require.Contains(t, []string{"55000", "0A000"}, pg.Code)
			} else {
				require.Equal(t, "55000", pg.Code)
			}
		}
	}
}
