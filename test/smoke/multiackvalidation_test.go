package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/alert"
	"github.com/target/goalert/escalation"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

type multiAckCycle struct {
	ID        string
	MultiAck  bool
	StartedAt time.Time
}

func multiAckCycles(t *testing.T, h *harness.Harness, alertID int) map[string]multiAckCycle {
	t.Helper()
	rows, err := h.App().DB().Query(`SELECT id, user_id, multi_ack, started_at FROM notification_policy_cycles WHERE alert_id = $1`, alertID)
	require.NoError(t, err)
	defer rows.Close()
	result := make(map[string]multiAckCycle)
	for rows.Next() {
		var userID string
		var cycle multiAckCycle
		require.NoError(t, rows.Scan(&cycle.ID, &userID, &cycle.MultiAck, &cycle.StartedAt))
		_, duplicate := result[userID]
		require.False(t, duplicate, "no duplicate cycles for the same user/alert")
		result[userID] = cycle
	}
	require.NoError(t, rows.Err())
	return result
}

func multiAckStatus(t *testing.T, h *harness.Harness, alertID int, want string) {
	t.Helper()
	var status string
	require.NoError(t, h.App().DB().QueryRow(`SELECT status FROM alerts WHERE id = $1`, alertID).Scan(&status))
	require.Equal(t, want, status)
	response := h.GraphQLQuery2(fmt.Sprintf(`{alert(id:%d){status}}`, alertID))
	require.Empty(t, response.Errors)
	var data struct{ Alert struct{ Status string } }
	require.NoError(t, json.Unmarshal(response.Data, &data))
	gqlStatus := map[string]string{"active": "StatusAcknowledged", "triggered": "StatusUnacknowledged", "closed": "StatusClosed"}
	require.Equal(t, gqlStatus[want], data.Alert.Status)
}

func multiAckLogUsers(t *testing.T, h *harness.Harness, alertID int, want ...string) {
	t.Helper()
	rows, err := h.App().DB().Query(`SELECT sub_user_id FROM alert_logs WHERE alert_id = $1 AND event = 'acknowledged' ORDER BY id`, alertID)
	require.NoError(t, err)
	defer rows.Close()
	var users []string
	for rows.Next() {
		var userID string
		require.NoError(t, rows.Scan(&userID))
		users = append(users, userID)
	}
	require.NoError(t, rows.Err())
	require.ElementsMatch(t, want, users, "each accepted ACK has exactly one actor log")
}

func multiAckEdit(t *testing.T, h *harness.Harness, enabled bool) {
	t.Helper()
	// Preserve the accepted Step/Engine lock-order limitation: isolate the
	// configuration edit, then resume the real Engine to prove runtime behavior.
	pauseStepOrganizationEngine(t, h)
	response := h.GraphQLQuery2(fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,multiAck:%t})}`, h.UUID("esid"), enabled))
	require.Empty(t, response.Errors)
	require.NoError(t, h.App().Engine.Resume(t.Context()))
}

func multiAckFalseFixture() string {
	return strings.Replace(multiAckSQL, `{{uuid "eid"}}, true);`, `{{uuid "eid"}}, false);`, 1)
}

// The snapshot cases exercise the real Engine and provider boundary, not only
// the stored columns. Duplicate ACK eligibility deliberately follows the
// current Step, while existing notification rules follow the cycle snapshot.
func TestMultiAckValidationRuntimeMatrix(t *testing.T) {
	for _, tc := range []struct {
		name    string
		initial bool
		omitted bool
		edit    bool
	}{
		{name: "omitted existing step upgrades to false", omitted: true},
		{name: "explicit false"},
		{name: "explicit true", initial: true},
		{name: "false cycle survives step edit to true", edit: true},
		{name: "true cycle survives step edit to false", initial: true, edit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fixture, migration := multiAckSQL, ""
			if !tc.initial {
				fixture = multiAckFalseFixture()
			}
			if tc.omitted {
				fixture = strings.Replace(fixture, "(id, escalation_policy_id, multi_ack)", "(id, escalation_policy_id)", 1)
				fixture = strings.Replace(fixture, `{{uuid "eid"}}, false);`, `{{uuid "eid"}});`, 1)
				// Insert the existing Step before canonical migration 287; Start
				// then applies the immutable remainder through position 289.
				migration = "schedule-rotation-ep-labels"
			}
			h := harness.NewHarness(t, fixture, migration)
			defer h.Close()
			tw := h.Twilio(t)
			d1, d2 := tw.Device(h.Phone("1")), tw.Device(h.Phone("2"))
			d1.ExpectSMS("testing")
			d2.ExpectSMS("testing")
			before := multiAckCycles(t, h, 198)
			require.Len(t, before, 2)
			for _, c := range before {
				require.Equal(t, tc.initial, c.MultiAck)
			}
			current := tc.initial
			if tc.edit {
				current = !current
				multiAckEdit(t, h, current)
				require.Equal(t, before, multiAckCycles(t, h, 198), "editing a Step must not rewrite any existing cycle")
			}
			h.FastForward(time.Minute) // ACK is strictly newer than cycle creation.
			d1.SendSMS("ack198")
			d1.ExpectSMS("acknowledged")
			multiAckStatus(t, h, 198, "active") // first ACK immediately acknowledges.
			multiAckLogUsers(t, h, 198, h.UUID("u1"))
			h.FastForward(31 * time.Minute)
			h.Trigger()
			if tc.initial {
				d2.ExpectSMS("testing")
				cycles := multiAckCycles(t, h, 198)
				require.Len(t, cycles, 1)
				require.Equal(t, before[h.UUID("u2")], cycles[h.UUID("u2")])
			} else {
				require.Empty(t, multiAckCycles(t, h, 198))
			}
			tw.WaitAndAssert() // zero acker/stale-cycle delayed notifications.
			d2.SendSMS("ack198")
			if current {
				d2.ExpectSMS("acknowledged")
				multiAckLogUsers(t, h, 198, h.UUID("u1"), h.UUID("u2"))
			} else {
				d2.ExpectSMS("already acknowledged")
				multiAckLogUsers(t, h, 198, h.UUID("u1"))
			}
			multiAckStatus(t, h, 198, "active")
			d1.SendSMS("close198")
			d1.ExpectSMS("closed")
			h.FastForward(31 * time.Minute)
			h.Trigger()
			multiAckStatus(t, h, 198, "closed")
			require.Empty(t, multiAckCycles(t, h, 198))
			tw.WaitAndAssert()

			if tc.edit {
				fresh := h.CreateAlert(h.UUID("sid"), "new cycle after edit")
				d1.ExpectSMS("new cycle after edit")
				d2.ExpectSMS("new cycle after edit")
				cycles := multiAckCycles(t, h, fresh.ID())
				require.Len(t, cycles, 2)
				for _, c := range cycles {
					require.Equal(t, current, c.MultiAck)
				}
				h.FastForward(time.Minute)
				d1.SendSMS(fmt.Sprintf("ack%d", fresh.ID()))
				d1.ExpectSMS("acknowledged")
				h.FastForward(31 * time.Minute)
				h.Trigger()
				if current {
					d2.ExpectSMS("new cycle after edit")
				}
				tw.WaitAndAssert()
				fresh.Close()
				h.FastForward(31 * time.Minute)
				h.Trigger()
				require.Empty(t, multiAckCycles(t, h, fresh.ID()))
				require.Empty(t, multiAckCycles(t, h, 198), "fresh alert cannot revive the closed alert")
			}
		})
	}
}

func TestMultiAckValidationCloseCancelsDelayedRules(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			t.Parallel()
			fixture := multiAckSQL
			if !enabled {
				fixture = multiAckFalseFixture()
			}
			h := harness.NewHarness(t, fixture, "")
			defer h.Close()
			tw := h.Twilio(t)
			d1, d2 := tw.Device(h.Phone("1")), tw.Device(h.Phone("2"))
			d1.ExpectSMS("testing")
			d2.ExpectSMS("testing")
			h.FastForward(time.Minute)
			d1.SendSMS("ack198")
			d1.ExpectSMS("acknowledged")
			d1.SendSMS("close198")
			d1.ExpectSMS("closed")
			h.FastForward(31 * time.Minute)
			h.Trigger()
			multiAckStatus(t, h, 198, "closed")
			require.Empty(t, multiAckCycles(t, h, 198))
			tw.WaitAndAssert() // neither user's pending 30-minute rule fired.
		})
	}
}

func TestMultiAckValidationDefaultsAndConcurrentACK(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, multiAckSQL, "")
	defer h.Close()
	tw := h.Twilio(t)
	tw.Device(h.Phone("1")).ExpectSMS("testing")
	tw.Device(h.Phone("2")).ExpectSMS("testing")
	pauseStepOrganizationEngine(t, h)
	for _, table := range []string{"escalation_policy_steps", "notification_policy_cycles"} {
		var nullable, defaultValue string
		require.NoError(t, h.App().DB().QueryRow(`SELECT is_nullable, column_default FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = 'multi_ack'`, table).Scan(&nullable, &defaultValue))
		require.Equal(t, "NO", nullable)
		require.Equal(t, "false", defaultValue)
	}
	ctx := permission.UserContext(t.Context(), h.UUID("u1"), permission.RoleUser)
	step, err := h.App().EscalationStore.CreateStepTx(ctx, nil, &escalation.Step{PolicyID: h.UUID("eid"), DelayMinutes: 60})
	require.NoError(t, err)
	require.False(t, step.MultiAck, "omitted Go field is false")
	var stored bool
	require.NoError(t, h.App().DB().QueryRow(`SELECT multi_ack FROM escalation_policy_steps WHERE id = $1`, step.ID).Scan(&stored))
	require.False(t, stored)
	_, err = h.App().DB().Exec(`INSERT INTO notification_policy_cycles(alert_id,user_id) VALUES(198,$1)`, h.UUID("u1"))
	require.NoError(t, err)
	var falseCycles int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM notification_policy_cycles WHERE alert_id = 198 AND NOT multi_ack`).Scan(&falseCycles))
	require.Equal(t, 1, falseCycles, "omitted SQL cycle value is false")
	h.FastForward(time.Minute)
	results := make(chan error, 2)
	for _, name := range []string{"u1", "u2"} {
		ctx := permission.UserSourceContext(t.Context(), h.UUID(name), permission.RoleUser,
			&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()})
		go func(ctx context.Context) { results <- h.App().AlertStore.UpdateStatus(ctx, 198, alert.StatusActive) }(ctx)
	}
	require.NoError(t, <-results)
	require.NoError(t, <-results)
	multiAckStatus(t, h, 198, "active")
	multiAckLogUsers(t, h, 198, h.UUID("u1"), h.UUID("u2"))
	require.NoError(t, h.App().AlertStore.UpdateStatus(ctx, 198, alert.StatusClosed))
	require.NoError(t, h.App().Engine.Resume(t.Context()))
	h.FastForward(31 * time.Minute)
	h.Trigger()
	require.Empty(t, multiAckCycles(t, h, 198))
	tw.WaitAndAssert()
}

func TestMultiAckValidationSharedPolicyAndBoundedRepeat(t *testing.T) {
	t.Parallel()
	fixture := multiAckSQL + `
		INSERT INTO services(id,escalation_policy_id,name,organization_id)
		VALUES({{uuid "sid2"}},{{uuid "eid"}},'shared policy service',{{smokeOrganizationID}});
		INSERT INTO alerts(id,service_id,summary,dedup_key)
		VALUES(199,{{uuid "sid2"}},'shared policy alert','auto:2:multiack');
		UPDATE escalation_policies SET repeat = 1 WHERE id = {{uuid "eid"}};
		UPDATE escalation_policy_steps SET delay = 60 WHERE id = {{uuid "esid"}};
	`
	h := harness.NewHarness(t, fixture, "")
	defer h.Close()
	tw := h.Twilio(t)
	d1, d2 := tw.Device(h.Phone("1")), tw.Device(h.Phone("2"))
	for _, d := range []harness.PhoneDevice{d1, d2} {
		d.ExpectSMS("testing")
		d.ExpectSMS("shared policy alert")
	}
	for _, id := range []int{198, 199} {
		require.Len(t, multiAckCycles(t, h, id), 2)
		for _, c := range multiAckCycles(t, h, id) {
			require.True(t, c.MultiAck)
		}
	}
	h.FastForward(time.Minute)
	d1.SendSMS("ack198")
	d1.ExpectSMS("acknowledged")
	d1.SendSMS("close199")
	d1.ExpectSMS("closed")
	h.FastForward(31 * time.Minute)
	h.Trigger()
	d2.ExpectSMS("testing")
	tw.WaitAndAssert()
	h.FastForward(31 * time.Minute)
	h.Trigger()
	// ACK pauses ordinary repeat escalation even while B's cycle continues.
	var loops int
	require.NoError(t, h.App().DB().QueryRow(`SELECT loop_count FROM escalation_policy_state WHERE alert_id = 198`).Scan(&loops))
	require.Zero(t, loops)
	require.Len(t, multiAckCycles(t, h, 198), 1)
	require.Empty(t, multiAckCycles(t, h, 199))
	tw.WaitAndAssert()
	// Explicit escalation starts fresh cycles; repeating once increments the
	// existing counter and does not revive the other Service's closed alert.
	h.Escalate(198, 0)
	d1.ExpectSMS("testing")
	d2.ExpectSMS("testing")
	require.NoError(t, h.App().DB().QueryRow(`SELECT loop_count FROM escalation_policy_state WHERE alert_id = 198`).Scan(&loops))
	require.Equal(t, 1, loops)
	var cycleCount int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM notification_policy_cycles WHERE alert_id = 198`).Scan(&cycleCount))
	require.Equal(t, 3, cycleCount, "one surviving old B cycle and two fresh cycles, exactly as upstream")
	h.FastForward(31 * time.Minute)
	h.Trigger()
	d1.ExpectSMS("testing")
	d2.ExpectSMS("testing")
	h.FastForward(31 * time.Minute)
	h.Trigger()
	tw.WaitAndAssert()
	require.NoError(t, h.App().DB().QueryRow(`SELECT loop_count FROM escalation_policy_state WHERE alert_id = 198`).Scan(&loops))
	require.Equal(t, 1, loops, "bounded repeat stops at its configured count")
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM notification_policy_cycles WHERE alert_id = 198`).Scan(&cycleCount))
	require.Equal(t, 3, cycleCount, "ticks cannot multiply cycles after the configured repeat limit")
	d1.SendSMS("close198")
	d1.ExpectSMS("closed")
	h.FastForward(2 * time.Hour)
	h.Trigger()
	require.Empty(t, multiAckCycles(t, h, 198))
	require.Empty(t, multiAckCycles(t, h, 199))
	tw.WaitAndAssert()
}
