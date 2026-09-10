package smoke

import (
	"testing"

	"github.com/target/goalert/test/smoke/harness"
)

// TestSlackDM tests that slack DMs are sent when configured.
func TestSlackDM(t *testing.T) {
	t.Parallel()

	sql := `
	insert into users (id, name, email, role) 
	values 
		({{uuid "user"}}, 'bob', 'joe', 'user');
	insert into user_contact_methods (id, user_id, name, type, value, enable_status_updates)
	values
		({{uuid "cm1"}}, {{uuid "user"}}, 'personal', 'SLACK_DM', {{slackUserID "bob"}}, true);
	insert into auth_subjects (user_id, subject_id, provider_id, cm_id)
	values
		({{uuid "user"}}, {{slackUserID "bob"}}, 'slack:' || {{slackTeamID}}, {{uuid "cm1"}});

	insert into user_notification_rules (user_id, contact_method_id, delay_minutes) 
	values
		({{uuid "user"}}, {{uuid "cm1"}}, 0),
		({{uuid "user"}}, {{uuid "cm1"}}, 30);

	insert into escalation_policies (id, name, organization_id)
	values
		({{uuid "eid"}}, 'esc policy', {{smokeOrganizationID}});
	insert into escalation_policy_steps (id, escalation_policy_id) 
	values
		({{uuid "esid"}}, {{uuid "eid"}});
	insert into escalation_policy_actions (escalation_policy_step_id, user_id) 
	values 
		({{uuid "esid"}}, {{uuid "user"}});

	insert into services (id, escalation_policy_id, name, organization_id)
	values
		({{uuid "sid"}}, {{uuid "eid"}}, 'service', {{smokeOrganizationID}});

`
	h := harness.NewHarness(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1")
	defer h.Close()
	h.SetConfigValue("Slack.InteractiveMessages", "true")
	h.Trigger() // the user's account should get "linked" via compat mgr

	h.CreateAlert(h.UUID("sid"), "testing")
	msg := h.Slack().User("bob").ExpectMessage("testing")
	msg.Action("Close").Click()

	updated := msg.ExpectUpdate()
	updated.AssertText("Closed", "testing")
	updated.AssertActions()
}
