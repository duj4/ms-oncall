package smoke

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
)

func TestServiceCascadePG11LifecycleAndPG12ExcludedResources(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	root := h.UUID("service-b")
	owner := h.UUID("user-a")
	alert := sd3Alert(t, h, root, "triggered")
	cm, nr, channel, cycle := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO user_contact_methods(id,user_id,name,type,value,pending) VALUES($1,$2,'SD3 CM','WEBHOOK','http://localhost/SD3-synthetic',false)`, []any{cm, owner}},
		{`INSERT INTO user_notification_rules(id,user_id,contact_method_id) VALUES($1,$2,$3)`, []any{nr, owner, cm}},
		{`INSERT INTO notification_channels(id,name,type,value) VALUES($1,'SD3 lifecycle','WEBHOOK','http://localhost/SD3-channel')`, []any{channel}},
		{`INSERT INTO alert_data(alert_id,metadata) VALUES($1,'{"synthetic":"SD3_DATA_SENTINEL"}')`, []any{alert}},
		{`INSERT INTO alert_feedback(alert_id,noise_reason) VALUES($1,'SD3_FEEDBACK_SENTINEL')`, []any{alert}},
		{`INSERT INTO alert_metrics(alert_id,service_id,closed_at) VALUES($1,$2,now())`, []any{alert, root}},
		{`INSERT INTO alert_status_subscriptions(alert_id,contact_method_id,last_alert_status) VALUES($1,$2,'triggered')`, []any{alert, cm}},
		{`INSERT INTO notification_policy_cycles(id,alert_id,user_id) VALUES($1,$2,$3)`, []any{cycle, alert, owner}},
		{`INSERT INTO pending_signals(dest_id,service_id,params) VALUES($1,$2,'{"synthetic":"SD3_SIGNAL_SENTINEL"}')`, []any{channel, root}},
		{`INSERT INTO heartbeat_monitors(id,service_id,name,heartbeat_interval) VALUES($1,$2,'SD3 excluded',interval '5 minutes')`, []any{uuid.New(), root}},
		{`INSERT INTO labels(tgt_service_id,key,value) VALUES($1,'SD3_EXCLUDED_KEY','SD3_EXCLUDED_VALUE')`, []any{root}},
	} {
		_, err := db.Exec(q.sql, q.args...)
		require.NoError(t, err)
	}
	var logID int64
	require.NoError(t, db.QueryRow(`INSERT INTO alert_logs(alert_id,event,message) VALUES($1,'created','SD3_LOG_SENTINEL') RETURNING id`, alert).Scan(&logID))
	var beforeLog string
	require.NoError(t, db.QueryRow(`SELECT to_jsonb(l)::text FROM alert_logs l WHERE id=$1`, logID).Scan(&beforeLog))
	direct, arrayOnly := uuid.New(), uuid.New()
	_, err := db.Exec(`INSERT INTO outgoing_messages(id,channel_id,message_type,last_status,alert_id,service_id,escalation_policy_id,cycle_id)
	 VALUES($1,$2,'alert_notification','failed',$3,$4,$5,$6)`, direct, channel, alert, root, h.UUID("policy-b"), cycle)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO outgoing_messages(id,channel_id,message_type,last_status,status_alert_ids) VALUES($1,$2,'alert_status_update_bundle','failed',ARRAY[$3::bigint])`, arrayOnly, channel, alert)
	require.NoError(t, err)
	var beforeArray string
	require.NoError(t, db.QueryRow(`SELECT to_jsonb(m)::text FROM outgoing_messages m WHERE id=$1`, arrayOnly).Scan(&beforeArray))
	// CONTRACT ADAPTATION: retain the entire original lifecycle fixture. Its
	// Label/Signal/Message shapes are unsupported, independent of Alert status.
	input := []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)}
	before, audits := serviceManagementSnapshot(t, h), smokeContract4SuccessState(t, h)
	_, err = smokeDeletionPreview(t, h, sd3System(), input)
	smokeDeletionCode(t, err, ds.DeletionUnavailable)
	smokeContract4Reject(t, h, sd3App(h), sd3System(), input, nil, ds.DeletionUnavailable)
	require.Equal(t, before, serviceManagementSnapshot(t, h))
	require.Equal(t, audits, smokeContract4SuccessState(t, h))
	// NEW LEGAL EQUIVALENT COVERAGE: isolate active-alert BLOCK from the
	// unsupported fixture, then exercise a distinct approved closed cascade.
	for _, status := range []string{"active", "triggered"} {
		blocked := smokeContract4Service(t, h, false)
		id := sd3Alert(t, h, blocked, status)
		smokeContract4Blocked(t, h, sd3App(h), []assignment.RawTarget{sd3Target(assignment.TargetTypeService, blocked)})
		require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM alerts WHERE id=$1 AND status=$2`, id, status))
	}
	for _, shape := range []string{"message", "signal", "label"} {
		unsupported := smokeContract4Service(t, h, false)
		switch shape {
		case "message":
			// FIXTURE REPAIR: the original migrated Message check requires
			// actual Alert, Service and Policy identities together.
			messageAlert := sd3Alert(t, h, unsupported, "closed")
			sd8Exec(t, h, `INSERT INTO outgoing_messages(id,channel_id,message_type,last_status,service_id,alert_id,escalation_policy_id) VALUES($1,$2,'alert_notification','failed',$3,$4,$5)`, uuid.New(), channel, unsupported, messageAlert, h.UUID("policy-b"))
		case "signal":
			sd8Exec(t, h, `INSERT INTO pending_signals(dest_id,service_id,params) VALUES($1,$2,'{}')`, channel, unsupported)
		case "label":
			sd8Exec(t, h, `INSERT INTO labels(tgt_service_id,key,value) VALUES($1,'closure-unsupported','synthetic')`, unsupported)
		}
		bad := []assignment.RawTarget{sd3Target(assignment.TargetTypeService, unsupported)}
		_, previewErr := smokeDeletionPreview(t, h, sd3System(), bad)
		smokeDeletionCode(t, previewErr, ds.DeletionUnavailable)
		smokeContract4Reject(t, h, sd3App(h), sd3System(), bad, nil, ds.DeletionUnavailable)
	}
	legal := smokeContract4Service(t, h, false)
	closed := sd3Alert(t, h, legal, "closed")
	_, safe := sd3Key(t, h, legal)
	var favorite int64
	require.NoError(t, db.QueryRow(`INSERT INTO user_favorites(user_id,tgt_service_id) VALUES($1,$2) RETURNING id`, owner, legal).Scan(&favorite))
	sd8Exec(t, h, `INSERT INTO alert_data(alert_id,metadata) VALUES($1,'{"synthetic":"SD3_DATA_SENTINEL"}')`, closed)
	sd8Exec(t, h, `INSERT INTO alert_feedback(alert_id,noise_reason) VALUES($1,'SD3_FEEDBACK_SENTINEL')`, closed)
	sd8Exec(t, h, `INSERT INTO alert_metrics(alert_id,service_id,closed_at) VALUES($1,$2,now())`, closed, legal)
	ok, err := smokeDeleteAll(t, h, sd3App(h), sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeService, legal)})
	require.NoError(t, err)
	require.True(t, ok)
	effects := sd3Effects(t, h, legal)
	require.Len(t, effects, 3)
	seen := map[string]bool{}
	for _, effect := range effects {
		require.False(t, seen[effect.EffectID.String()])
		seen[effect.EffectID.String()] = true
		switch effect.ResourceType {
		case "alert":
			require.Equal(t, closed, *effect.ResourceNumericID)
		case "integration_key":
			require.Equal(t, safe, *effect.ResourceUUID)
		case "service_favorite":
			require.Equal(t, favorite, *effect.ResourceNumericID)
		default:
			t.Fatal("unapproved Service effect")
		}
	}
	for _, table := range []string{"alert_data", "alert_feedback", "alert_metrics"} {
		require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM `+table+` WHERE alert_id=$1`, closed))
	}
	require.Zero(t, serviceManagementCount(t, h, "services", legal))
	// Original excluded/history rows were never made deletable by the legal
	// fixture, including array-only message history and every sentinel.
	var afterLog, afterArray string
	require.NoError(t, db.QueryRow(`SELECT to_jsonb(l)::text FROM alert_logs l WHERE id=$1`, logID).Scan(&afterLog))
	require.Equal(t, beforeLog, afterLog)
	require.NoError(t, db.QueryRow(`SELECT to_jsonb(m)::text FROM outgoing_messages m WHERE id=$1`, arrayOnly).Scan(&afterArray))
	require.Equal(t, beforeArray, afterArray)
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM outgoing_messages WHERE id=$1`, direct))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM message_status_history WHERE message_id=$1`, arrayOnly))
	for _, row := range []struct{ table, id string }{{"users", owner}, {"escalation_policies", h.UUID("policy-b")}, {"user_contact_methods", cm.String()}, {"user_notification_rules", nr.String()}} {
		require.Equal(t, 1, serviceManagementCount(t, h, row.table, row.id))
	}
	for _, sentinel := range []string{"SD3_DATA_SENTINEL", "SD3_FEEDBACK_SENTINEL", "SD3_LOG_SENTINEL", "SD3_SIGNAL_SENTINEL", "SD3_EXCLUDED_KEY", "SD3_EXCLUDED_VALUE"} {
		require.NotContains(t, sd1Rows(t, h), sentinel)
	}
	t.Log("PARTIAL LEGAL COVERAGE: original full lifecycle Unsupported and active/triggered BLOCK retained; independent closed cascade/B2 restored; old Message/Signal/Label success NOT REACHABLE")
}
