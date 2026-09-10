package smoke

import (
	"testing"
	"time"

	"github.com/target/goalert/test/smoke/harness"
)

// TestPostCycleRules checks that new rules added after the last
// rule of a policy executes are handled the same way as during a policy cycle.
func TestPostCycleRules(t *testing.T) {
	t.Parallel()

	sql := `
	insert into users (id, name, email) 
	values 
		({{uuid "uid"}}, 'bob', 'joe');

	insert into user_contact_methods (id, user_id, name, type, value) 
	values
		({{uuid "cid"}}, {{uuid "uid"}}, 'personal', 'SMS', {{phone "1"}}),
		({{uuid "cid2"}}, {{uuid "uid"}}, 'personal2', 'SMS', {{phone "2"}});

	insert into user_notification_rules (user_id, contact_method_id, delay_minutes) 
	values
		({{uuid "uid"}}, {{uuid "cid2"}}, 0);

	insert into escalation_policies (id, name, repeat, organization_id)
	values 
		({{uuid "eid"}}, 'esc policy', -1, {{smokeOrganizationID}});
	insert into escalation_policy_steps (id, escalation_policy_id, delay) 
	values 
		({{uuid "esid"}}, {{uuid "eid"}}, 60);

	insert into escalation_policy_actions (escalation_policy_step_id, user_id) 
	values
		({{uuid "esid"}}, {{uuid "uid"}});

	insert into services (id, escalation_policy_id, name, organization_id)
	values
		({{uuid "sid"}}, {{uuid "eid"}}, 'service', {{smokeOrganizationID}});

	insert into alerts (service_id, summary, dedup_key)
	values
		({{uuid "sid"}}, 'testing', 'auto:1:smoke:postcyclerules_test:1:1');

`

	h := harness.NewHarness(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1")
	defer h.Close()

	tw := h.Twilio(t)
	d1 := tw.Device(h.Phone("1"))
	d2 := tw.Device(h.Phone("2"))

	d2.ExpectSMS("testing")

	// ADD RULES
	h.AddNotificationRule(h.UUID("uid"), h.UUID("cid"), 0)
	h.AddNotificationRule(h.UUID("uid"), h.UUID("cid"), 30)

	// ensure no notification for instant rule
	tw.WaitAndAssert()

	h.FastForward(30 * time.Minute)

	d1.ExpectSMS("testing")
}
