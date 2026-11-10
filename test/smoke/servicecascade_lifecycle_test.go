package smoke

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
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
	ok, err := sd3App(h).Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)})
	require.NoError(t, err)
	require.True(t, ok)
	effects := sd3Effects(t, h, root)
	require.Len(t, effects, 1)
	require.Equal(t, alert, *effects[0].ResourceNumericID)
	for _, table := range []string{"alert_data", "alert_feedback", "alert_metrics", "alert_status_subscriptions", "escalation_policy_state", "notification_policy_cycles", "pending_signals", "heartbeat_monitors", "labels"} {
		var count int
		require.NoError(t, db.QueryRow(`SELECT count(*) FROM `+table).Scan(&count))
		require.Zero(t, count, table)
	}
	var afterLog, afterArray string
	require.NoError(t, db.QueryRow(`SELECT to_jsonb(l)::text FROM alert_logs l WHERE id=$1`, logID).Scan(&afterLog))
	require.Equal(t, beforeLog, afterLog)
	require.NoError(t, db.QueryRow(`SELECT to_jsonb(m)::text FROM outgoing_messages m WHERE id=$1`, arrayOnly).Scan(&afterArray))
	require.Equal(t, beforeArray, afterArray)
	var directMessages, directHistory, arrayHistory int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM outgoing_messages WHERE id=$1`, direct).Scan(&directMessages))
	require.Zero(t, directMessages)
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM message_status_history WHERE message_id=$1`, direct).Scan(&directHistory))
	require.Zero(t, directHistory)
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM message_status_history WHERE message_id=$1`, arrayOnly).Scan(&arrayHistory))
	require.Equal(t, 1, arrayHistory)
	for _, row := range []struct{ table, id string }{{"users", owner}, {"escalation_policies", h.UUID("policy-b")}, {"user_contact_methods", cm.String()}, {"user_notification_rules", nr.String()}} {
		require.Equal(t, 1, serviceManagementCount(t, h, row.table, row.id))
	}
	for _, sentinel := range []string{"SD3_DATA_SENTINEL", "SD3_FEEDBACK_SENTINEL", "SD3_LOG_SENTINEL", "SD3_SIGNAL_SENTINEL", "SD3_EXCLUDED_KEY", "SD3_EXCLUDED_VALUE"} {
		require.NotContains(t, sd1Rows(t, h), sentinel)
	}
}
