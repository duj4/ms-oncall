package smoke

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/app"
	"github.com/target/goalert/devtools/pgmocktime"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/test/smoke/harness"
)

// The missing JSON reference must be filtered from both the live membership and
// ordinary Webhook without rewriting the temporary schedule or repeating sends.
func TestWebhookOnCallTempScheduleMissingUser(t *testing.T) {
	t.Parallel()
	r := newSupportedWebhookReceiver(t)
	fixture := fmt.Sprintf(`
		INSERT INTO users(id,name,email) VALUES
			({{uuid "u1"}},'First','first@example.invalid'),({{uuid "u2"}},'Second','second@example.invalid');
		INSERT INTO schedules(id,name,time_zone,organization_id)
			VALUES({{uuid "schedule"}},'Supported schedule','Asia/Shanghai',{{smokeOrganizationID}});
		INSERT INTO notification_channels(id,type,name,value)
			VALUES({{uuid "webhook"}},'WEBHOOK','Missing user receiver','%s/missing-user');
		INSERT INTO schedule_data(schedule_id,data) VALUES({{uuid "schedule"}},jsonb_build_object('V1',jsonb_build_object(
			'OnCallNotificationRules',jsonb_build_array(jsonb_build_object('ChannelID',{{uuid "webhook"}}::text)),
			'TemporarySchedules',jsonb_build_array(jsonb_build_object(
				'Start',now()-interval '1 hour','End',now()+interval '24 hours',
				'Shifts',jsonb_build_array(
					jsonb_build_object('Start',now()-interval '1 hour','End',now()+interval '24 hours','UserID',{{uuid "u1"}}::text),
					jsonb_build_object('Start',now()-interval '1 hour','End',now()+interval '24 hours','UserID',{{uuid "u2"}}::text),
					jsonb_build_object('Start',now()-interval '1 hour','End',now()+interval '24 hours','UserID',{{uuid "deleted-user"}}::text)
				)
			))
		)));
	`, r.URL)
	h := harness.NewStoppedHarness(t, fixture, nil, "")
	defer h.Close()
	const publicURL = "https://core.test.invalid"
	h.StartWithAppCfgHook(func(c *app.Config) {
		c.InitialConfig.General.PublicURL = publicURL
	})

	// Start restores speed=1; freeze again on this Harness-owned database before
	// establishing a checkpoint. Background Engine ticks remain enabled.
	var database string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&database))
	clock, err := pgmocktime.New(t.Context(), harness.DBURL(database))
	require.NoError(t, err)
	defer clock.Close()
	require.NoError(t, clock.SetSpeed(t.Context(), 0))
	initialTime := h.Now()

	waitSent := func() {
		t.Helper()
		require.Eventually(t, func() bool {
			var sent int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM outgoing_messages
				WHERE schedule_id=$1 AND last_status='sent' AND sent_at IS NOT NULL`, h.UUID("schedule")).Scan(&sent))
			return sent >= 1
		}, 10*time.Second, 10*time.Millisecond, "wait for real HTTP completion to become durable")
	}
	h.Trigger()
	require.Eventually(t, func() bool { return len(r.events("")) >= 1 }, 10*time.Second, 10*time.Millisecond)
	waitSent()
	h.Trigger() // complete another full cycle, including message-result draining
	waitSent()

	type checkpoint struct{ Outbox, History, Members, Data string }
	readCheckpoint := func() checkpoint {
		t.Helper()
		tx, err := h.App().DB().BeginTx(t.Context(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
		require.NoError(t, err)
		defer harness.SQLRollback(t, "read on-call checkpoint", tx)
		var s checkpoint
		// Include all rows for this schedule, regardless of type or status. Keep
		// destination/provider internals out of diagnostics and snapshots.
		require.NoError(t, tx.QueryRowContext(t.Context(), `SELECT coalesce(jsonb_agg(jsonb_build_object(
			'id',id,'message_type',message_type,'schedule_id',schedule_id,'channel_id',channel_id,
			'contact_method_id',contact_method_id,'alert_id',alert_id,'last_status',last_status,
			'last_status_at',last_status_at,'status_details',status_details,'sent_at',sent_at,
			'retry_count',retry_count,'next_retry_at',next_retry_at,'sending_deadline',sending_deadline
		) ORDER BY id),'[]'::jsonb)::text FROM outgoing_messages WHERE schedule_id=$1`, h.UUID("schedule")).Scan(&s.Outbox))
		require.NoError(t, tx.QueryRowContext(t.Context(), `SELECT coalesce(jsonb_agg(to_jsonb(h) ORDER BY h.id),'[]'::jsonb)::text
			FROM message_status_history h JOIN outgoing_messages m ON m.id=h.message_id
			WHERE m.schedule_id=$1`, h.UUID("schedule")).Scan(&s.History))
		require.NoError(t, tx.QueryRowContext(t.Context(), `SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY user_id,start_time),'[]'::jsonb)::text
			FROM schedule_on_call_users s WHERE schedule_id=$1 AND end_time IS NULL`, h.UUID("schedule")).Scan(&s.Members))
		require.NoError(t, tx.QueryRowContext(t.Context(), `SELECT data::text FROM schedule_data WHERE schedule_id=$1`, h.UUID("schedule")).Scan(&s.Data))
		require.NoError(t, tx.Commit())
		return s
	}
	initial := readCheckpoint()
	receipts := r.events("")
	require.Len(t, receipts, 1, "all events, including unexpected types and duplicate requests")
	require.Equal(t, "/missing-user", receipts[0].Path)
	require.Equal(t, "ScheduleOnCallUsers", receipts[0].Type)
	supportedOnCallPayload(t, h, receipts[0], h.UUID("u1"), h.UUID("u2"))
	var payload POSTDataOnCallNotification
	require.NoError(t, json.Unmarshal(receipts[0].Body, &payload))
	require.Equal(t, publicURL+"/schedules/"+h.UUID("schedule"), payload.ScheduleURL)
	for _, u := range payload.Users {
		require.Equal(t, publicURL+"/users/"+u.ID, u.URL)
	}
	// Require the ordinary top-level wire shape, rather than a Gateway envelope.
	var wire map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(receipts[0].Body, &wire))
	require.Len(t, wire, 6)
	for _, key := range []string{"AppName", "Type", "ScheduleID", "ScheduleName", "ScheduleURL", "Users"} {
		require.Contains(t, wire, key)
	}

	var messages []struct {
		ID              string
		MessageType     string     `json:"message_type"`
		ScheduleID      string     `json:"schedule_id"`
		ChannelID       string     `json:"channel_id"`
		ContactMethodID *string    `json:"contact_method_id"`
		AlertID         *int       `json:"alert_id"`
		LastStatus      string     `json:"last_status"`
		SentAt          *time.Time `json:"sent_at"`
		RetryCount      int        `json:"retry_count"`
		NextRetryAt     *time.Time `json:"next_retry_at"`
		SendingDeadline *time.Time `json:"sending_deadline"`
	}
	require.NoError(t, json.Unmarshal([]byte(initial.Outbox), &messages))
	require.Len(t, messages, 1, "count pending/failed/other rows too")
	message := messages[0]
	require.NotEmpty(t, message.ID)
	require.Equal(t, "schedule_on_call_notification", message.MessageType)
	require.Equal(t, h.UUID("schedule"), message.ScheduleID)
	require.Equal(t, h.UUID("webhook"), message.ChannelID)
	require.Nil(t, message.ContactMethodID)
	require.Nil(t, message.AlertID)
	require.Equal(t, "sent", message.LastStatus)
	require.NotNil(t, message.SentAt)
	require.Zero(t, message.RetryCount)
	require.Nil(t, message.NextRetryAt)
	require.Nil(t, message.SendingDeadline)
	var history []struct {
		ID        int64
		MessageID string `json:"message_id"`
		Status    string
		Details   string `json:"status_details"`
	}
	require.NoError(t, json.Unmarshal([]byte(initial.History), &history))
	var progression []string
	for i, row := range history {
		require.Equal(t, message.ID, row.MessageID)
		require.NotContains(t, row.Details, r.URL, "history must not disclose the destination")
		if i > 0 {
			require.Greater(t, row.ID, history[i-1].ID, "history is ordered by identity, not equal timestamps")
		}
		// The sender may report the same status more than once internally. Keep
		// every persisted row while checking the successful state progression.
		if len(progression) == 0 || progression[len(progression)-1] != row.Status {
			progression = append(progression, row.Status)
		}
	}
	require.Equal(t, []string{"pending", "sending", "sent"}, progression, "no failed or unexpected transition")
	var members []struct {
		UserID string `json:"user_id"`
	}
	require.NoError(t, json.Unmarshal([]byte(initial.Members), &members))
	var memberIDs []string
	for _, member := range members {
		memberIDs = append(memberIDs, member.UserID)
	}
	require.ElementsMatch(t, []string{h.UUID("u1"), h.UUID("u2")}, memberIDs)

	assertFixture := func() {
		t.Helper()
		var missingUsers, missingShifts int
		require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM users WHERE id=$1`, h.UUID("deleted-user")).Scan(&missingUsers))
		require.Zero(t, missingUsers, "the nonexistent user must never be inserted")
		require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM schedule_on_call_users WHERE schedule_id=$1 AND user_id=$2`, h.UUID("schedule"), h.UUID("deleted-user")).Scan(&missingShifts))
		require.Zero(t, missingShifts, "no historical or active shift for the missing user")
		var sameData bool
		require.NoError(t, h.App().DB().QueryRow(`SELECT data=$2::jsonb FROM schedule_data WHERE schedule_id=$1`, h.UUID("schedule"), initial.Data).Scan(&sameData))
		require.True(t, sameData, "compare stored JSONB semantically")
		var data schedule.Data
		require.NoError(t, json.Unmarshal([]byte(initial.Data), &data))
		active, users := data.TempOnCall(h.Now())
		require.True(t, active, "temporary schedule remains active throughout observation")
		require.ElementsMatch(t, []string{h.UUID("u1"), h.UUID("u2"), h.UUID("deleted-user")}, func() []string {
			var ids []string
			for _, id := range users {
				ids = append(ids, id.String())
			}
			return ids
		}(), "all three JSON references remain; filtering is not cleanup")
	}
	assertStable := func() {
		t.Helper()
		require.Equal(t, receipts, r.events(""), "no unexpected or duplicate HTTP receipt")
		current := readCheckpoint()
		require.JSONEq(t, initial.Outbox, current.Outbox, "same complete Outbox identities/count/states")
		require.JSONEq(t, initial.History, current.History, "same complete ordered history and details")
		require.JSONEq(t, initial.Members, current.Members, "same active shifts")
		require.JSONEq(t, initial.Data, current.Data, "same persisted schedule definition")
		assertFixture()
	}
	assertStable()
	t.Logf("F04 initial receipt=%s outbox=%s history=%s active=%s missing-user=%s absent; data=%s", receipts[0].Body, initial.Outbox, initial.History, initial.Members, h.UUID("deleted-user"), initial.Data)
	for range 3 {
		h.Trigger()
		waitSent()
		assertStable()
		require.Equal(t, initialTime, h.Now(), "database time is frozen after startup")
	}
	h.FastForward(time.Hour)
	for range 3 {
		h.Trigger()
		waitSent()
		assertStable()
	}
	require.Equal(t, initialTime.Add(time.Hour), h.Now())
	// Keep the Engine and real sender available during a bounded asynchronous
	// negative observation, then finish with a complete cycle and exact checks.
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		assertStable()
		time.Sleep(25 * time.Millisecond)
	}
	h.Trigger()
	waitSent()
	assertStable()
	t.Logf("F04 stable: 3 frozen cycles, +1h and 3 further cycles, 1s asynchronous observation and final cycle; message=%s", message.ID)
}
