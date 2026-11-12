package smoke

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
	cmnr "github.com/target/goalert/user/cmnrdeleteaudit"
	audit "github.com/target/goalert/user/deleteaudit"
)

func TestUserDeleteAuditReceiptsPG(t *testing.T) {
	h := sd1Harness(t)
	u := sd7User(t, h)
	rot := sd6Root(t, h, "rotation", harness.SmokeOrganizationID)
	v, survivor := sd7User(t, h), sd7User(t, h)
	for i, user := range []string{u, v, survivor} {
		sd8Exec(t, h, `INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES($1,$2,$3,$4)`, uuid.NewString(), rot, user, i)
	}
	cm, _ := sd8CMNR(t, h, u)
	sd8Exec(t, h, `INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time,end_time) VALUES($1,$2,'2020-01-01','2020-01-02')`, h.UUID("schedule-a"), u)
	tx, err := h.App().DB().BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	e := audit.Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), OccurredAt: time.Now(), RootType: "user", Operation: "user.delete", ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", TargetOrgResolution: "unknown"}
	result, err := h.App().UserStore.DeleteManyForAuditTx(permission.SystemContext(t.Context(), "Engine"), tx, []string{u}, e, []audit.ExplicitIntent{{ResourceType: "contact_method", ID: uuid.MustParse(cm)}})
	if err != nil {
		var times string
		_ = tx.QueryRow(`SELECT before_value::text FROM pg_temp.sd8_user_delete_witness WHERE resource_type='schedule_on_call_history' LIMIT 1`).Scan(&times)
		t.Log("safe history", times)
	}
	require.NoError(t, err)
	require.Len(t, result.Targets, 1)
	require.Len(t, result.Receipts, 1)
	r := result.Receipts[0]
	require.NoError(t, r.Validate())
	require.LessOrEqual(t, r.CaptureHighUnits, audit.MaxCaptureUnits)
	require.LessOrEqual(t, r.ActiveJSONHighBytes, audit.MaxActiveJSONBytes)
	t.Logf("capture_high_units=%d active_json_high_bytes=%d effect_pages=%d", r.CaptureHighUnits, r.ActiveJSONHighBytes, r.EffectPages)
	raw, _ := json.Marshal(r.Event)
	var valid bool
	require.NoError(t, tx.QueryRow(`SELECT user_delete_header_valid($1::jsonb)`, string(raw)).Scan(&valid))
	require.True(t, valid, "header validation: %s", string(raw))
	require.NoError(t, audit.AppendReceipt(t.Context(), tx, r))
	w := r.Witnesses[0]
	ev := cmnr.Event{SchemaVersion: 2, EventID: w.EventID, RequestID: w.RequestID, ExecutionID: w.ExecutionID, AttemptID: w.AttemptID, OccurredAt: e.OccurredAt, RootType: w.ResourceType, Operation: w.ResourceType + ".delete", RootID: w.ResourceID, RootOwnerUserID: w.OwnerID, TargetOrgResolution: w.TargetOrgResolution, RecordKind: "success_witness", Outcome: "committed", Reason: "deleted", Provenance: "EXPLICIT", DeletionMechanism: "fk_cascade", CauseRootType: "user", CauseRootID: w.CauseUserID, CauseEventID: w.CauseEventID, UserCauseWitness: &w, ActorKind: e.ActorKind, AuthoritySource: e.AuthoritySource, AuthorityRole: e.AuthorityRole, OrganizationRole: e.OrganizationRole}
	require.NoError(t, ev.Validate())
	require.NoError(t, cmnr.Append(t.Context(), tx, ev))
	_, err = tx.ExecContext(t.Context(), `SET CONSTRAINTS ALL IMMEDIATE`)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
}
