package smoke

import (
	"testing"

	"github.com/target/goalert/test/smoke/harness"
)

// TestMultiUser checks that if multiple users are assigned to a policy step,
// they all get their notifications.
func TestMultiUser(t *testing.T) {
	t.Parallel()

	sql := `
	insert into users (id, name, email) 
	values
		({{uuid "u1"}}, 'bob', 'joe'),
		({{uuid "u2"}}, 'ben', 'josh'),
		({{uuid "u3"}}, 'beth', 'jake');

	insert into user_contact_methods (id, user_id, name, type, value) 
	values
		({{uuid "c1"}}, {{uuid "u1"}}, 'personal', 'SMS', {{phone "1"}}),
		({{uuid "c2"}}, {{uuid "u2"}}, 'personal', 'SMS', {{phone "2"}}),
		({{uuid "c3"}}, {{uuid "u3"}}, 'personal', 'SMS', {{phone "3"}});

	insert into user_notification_rules (user_id, contact_method_id, delay_minutes) 
	values
		({{uuid "u1"}}, {{uuid "c1"}}, 0),
		({{uuid "u2"}}, {{uuid "c2"}}, 0),
		({{uuid "u3"}}, {{uuid "c3"}}, 0);

	insert into escalation_policies (id, name, repeat, organization_id)
	values 
		({{uuid "eid"}}, 'esc policy', -1, {{smokeOrganizationID}});
	insert into escalation_policy_steps (id, escalation_policy_id, delay) 
	values 
		({{uuid "esid"}}, {{uuid "eid"}}, 60);
	insert into escalation_policy_actions (escalation_policy_step_id, user_id) 
	values
		({{uuid "esid"}}, {{uuid "u1"}}),
		({{uuid "esid"}}, {{uuid "u2"}}),
		({{uuid "esid"}}, {{uuid "u3"}});

	insert into services (id, escalation_policy_id, name, organization_id)
	values
		({{uuid "sid"}}, {{uuid "eid"}}, 'service', {{smokeOrganizationID}});

	insert into alerts (service_id, summary, dedup_key)
	values
		({{uuid "sid"}}, 'testing', 'auto:1:smoke:multiuser_test:1:1');
	`

	h := harness.NewHarness(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1")
	defer h.Close()

	h.Twilio(t).Device(h.Phone("1")).ExpectSMS("testing")
	h.Twilio(t).Device(h.Phone("2")).ExpectSMS("testing")
	h.Twilio(t).Device(h.Phone("3")).ExpectSMS("testing")
}
