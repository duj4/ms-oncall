package smoke

import (
	"testing"
	"time"

	"github.com/target/goalert/test/smoke/harness"
)

// TestSlackNotification tests that slack channels are returned for configured users.
func TestSlackNotification(t *testing.T) {
	t.Parallel()

	sql := `
	insert into escalation_policies (id, name, repeat, organization_id)
	values
		({{uuid "eid"}}, 'esc policy', 1, {{smokeOrganizationID}});
	insert into escalation_policy_steps (id, escalation_policy_id, delay) 
	values
		({{uuid "esid"}}, {{uuid "eid"}}, 30);

	insert into notification_channels (id, type, name, value)
	values
		({{uuid "chan"}}, 'SLACK', '#test', {{slackChannelID "test"}});

	insert into escalation_policy_actions (escalation_policy_step_id, channel_id) 
	values 
		({{uuid "esid"}}, {{uuid "chan"}});

	insert into services (id, escalation_policy_id, name, organization_id)
	values
		({{uuid "sid"}}, {{uuid "eid"}}, 'service', {{smokeOrganizationID}});
`
	h := harness.NewHarness(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1")
	defer h.Close()

	h.CreateAlert(h.UUID("sid"), "testing")
	msg := h.Slack().Channel("test").ExpectMessage("testing")
	msg.AssertColor("#862421")

	h.FastForward(time.Hour)
	// should broadcast reply to channel
	msg.ExpectBroadcastReply("Alert #1")
}
