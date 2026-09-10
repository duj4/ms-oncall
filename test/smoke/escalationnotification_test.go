package smoke

import (
	"testing"
	"time"

	"github.com/target/goalert/test/smoke/harness"
)

// TestEscalationNotification ensures that notification rules
// don't repeat during an escalation step, and continue to completion.
func TestEscalationNotification(t *testing.T) {
	t.Parallel()
	sql := `
	insert into users (id, name, email) 
	values 
		({{uuid "uid"}}, 'bob', 'joe');
	insert into user_contact_methods (id, user_id, name, type, value) 
	values
		({{uuid "c1"}}, {{uuid "uid"}}, 'personal', 'SMS', {{phone "1"}}),
		({{uuid "c2"}}, {{uuid "uid"}}, 'personal', 'VOICE', {{phone "2"}});

	insert into user_notification_rules (user_id, contact_method_id, delay_minutes) 
	values
		({{uuid "uid"}}, {{uuid "c1"}}, 0),
		({{uuid "uid"}}, {{uuid "c2"}}, 0),
		({{uuid "uid"}}, {{uuid "c1"}}, 30);

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
		({{uuid "sid"}}, 'testing', 'auto:1:smoke:escalationnotification_test:1:1');
`

	h := harness.NewHarness(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1")
	defer h.Close()

	tw := h.Twilio(t)
	d1 := tw.Device(h.Phone("1"))
	d2 := tw.Device(h.Phone("2"))

	d1.ExpectSMS("testing")
	d2.ExpectVoice("testing")

	h.Escalate(1, 0) // results in the start of a 2nd cycle

	d1.ExpectSMS("testing")
	d2.ExpectVoice("testing")

	h.FastForward(30 * time.Minute) // ensure both rules have elapsed

	// 1 sms from the first step, 1 from the escalated one, should be de-duplicated
	d1.ExpectSMS("testing")

	h.Escalate(1, 1)
	d1.ExpectSMS("testing")
	d2.ExpectVoice("testing")

	h.FastForward(30 * time.Minute)
	d1.ExpectSMS("testing")
}
