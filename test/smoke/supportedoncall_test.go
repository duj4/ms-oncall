package smoke

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/util/timeutil"
)

func supportedOnCallFixture(url string) string {
	return fmt.Sprintf(`
		INSERT INTO users(id,name,email) VALUES({{uuid "u1"}},'First','first@example.invalid'),({{uuid "u2"}},'Second','second@example.invalid');
		INSERT INTO schedules(id,name,time_zone,organization_id) VALUES({{uuid "schedule"}},'Supported schedule','Asia/Shanghai',{{smokeOrganizationID}});
		INSERT INTO schedule_rules(id,schedule_id,tgt_user_id,start_time,end_time) VALUES({{uuid "rule1"}},{{uuid "schedule"}},{{uuid "u1"}},'00:00:00','00:00:00');
		INSERT INTO notification_channels(id,type,name,value) VALUES
			({{uuid "change1"}},'WEBHOOK','First receiver','%s/change1'),({{uuid "change2"}},'WEBHOOK','Second receiver','%s/change2'),
			({{uuid "timed"}},'WEBHOOK','Timed receiver','%s/timed');
		INSERT INTO schedule_data(schedule_id,data) VALUES({{uuid "schedule"}},'{"V1":{"OnCallNotificationRules":[{"ChannelID":{{uuidJSON "change1"}}},{"ChannelID":{{uuidJSON "change2"}}}]}}');
	`, url, url, url)
}

func supportedOnCallPayload(t *testing.T, h *harness.Harness, receipt supportedWebhookReceipt, users ...string) {
	t.Helper()
	var payload POSTDataOnCallNotification
	require.NoError(t, json.Unmarshal(receipt.Body, &payload))
	require.Equal(t, "ScheduleOnCallUsers", payload.Type)
	require.Equal(t, h.UUID("schedule"), payload.ScheduleID)
	require.Equal(t, "Supported schedule", payload.ScheduleName)
	require.Contains(t, payload.ScheduleURL, h.UUID("schedule"))
	var got []string
	for _, u := range payload.Users {
		require.Contains(t, u.URL, u.ID)
		wantName := map[string]string{h.UUID("u1"): "First", h.UUID("u2"): "Second"}[u.ID]
		require.NotEmpty(t, wantName, "unexpected member")
		require.Equal(t, wantName, u.Name)
		got = append(got, u.ID)
	}
	require.ElementsMatch(t, users, got, "full current member set, not merely the added user")
}

func TestSupportedWebhookOnCallChanges(t *testing.T) {
	r := newSupportedWebhookReceiver(t)
	h := harness.NewHarness(t, supportedOnCallFixture(r.URL), "")
	defer h.Close()
	expect := func(count int, users ...string) {
		t.Helper()
		require.Eventually(t, func() bool { return len(r.events("")) >= count }, 10*time.Second, 10*time.Millisecond)
		events := r.events("")
		require.Len(t, events, count)
		require.ElementsMatch(t, []string{"/change1", "/change2"}, []string{events[count-2].Path, events[count-1].Path})
		for _, event := range events[count-2:] {
			supportedOnCallPayload(t, h, event, users...)
		}
	}
	expect(2, h.UUID("u1"))
	h.FastForward(time.Hour)
	h.Trigger()
	expect(2, h.UUID("u1"))
	// Isolate fixture edits from Engine locks; use existing Schedule calculations.
	pauseStepOrganizationEngine(t, h)
	_, err := h.App().DB().Exec(`INSERT INTO schedule_rules(id,schedule_id,tgt_user_id,start_time,end_time) VALUES($1,$2,$3,'00:00:00','00:00:00')`, h.UUID("rule2"), h.UUID("schedule"), h.UUID("u2"))
	require.NoError(t, err)
	require.NoError(t, h.App().Engine.Resume(t.Context()))
	h.Trigger()
	expect(4, h.UUID("u1"), h.UUID("u2"))
	pauseStepOrganizationEngine(t, h)
	_, err = h.App().DB().Exec(`DELETE FROM schedule_rules WHERE id=$1`, h.UUID("rule1"))
	require.NoError(t, err)
	require.NoError(t, h.App().Engine.Resume(t.Context()))
	h.Trigger()
	expect(6, h.UUID("u2"))
	h.FastForward(time.Hour)
	h.Trigger()
	expect(6, h.UUID("u2"))
}

func TestSupportedWebhookOnCallTimed(t *testing.T) {
	r := newSupportedWebhookReceiver(t)
	h := harness.NewHarness(t, supportedOnCallFixture(r.URL), "")
	defer h.Close()
	require.Eventually(t, func() bool { return len(r.events("")) == 2 }, 10*time.Second, 10*time.Millisecond)
	// Install the timed rule just before its next local deadline, independent of
	// the machine's start time. Existing unit tests retain weekday/missing-user cases.
	h.FastForwardToTime(timeutil.NewClock(8, 59), "Asia/Shanghai")
	h.Trigger()
	pauseStepOrganizationEngine(t, h)
	data := fmt.Sprintf(`{"V1":{"OnCallNotificationRules":[{"ChannelID":%q,"Time":"09:00"}]}}`, h.UUID("timed"))
	_, err := h.App().DB().Exec(`UPDATE schedule_data SET data=$1 WHERE schedule_id=$2`, data, h.UUID("schedule"))
	require.NoError(t, err)
	require.NoError(t, h.App().Engine.Resume(t.Context()))
	h.Trigger()
	require.Len(t, r.events(""), 2, "not before 09:00 in Schedule timezone")
	h.FastForward(time.Minute)
	h.Trigger()
	require.Eventually(t, func() bool { return len(r.events("")) >= 3 }, 10*time.Second, 10*time.Millisecond)
	events := r.events("")
	require.Len(t, events, 3)
	require.Equal(t, "/timed", events[2].Path)
	supportedOnCallPayload(t, h, events[2], h.UUID("u1"))
	h.FastForward(time.Hour)
	h.Trigger()
	require.Len(t, r.events(""), 3, "timed rule must not turn into an on-change or repeated notification")
}
