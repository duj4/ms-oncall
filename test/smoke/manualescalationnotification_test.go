package smoke

import (
	"testing"

	"github.com/target/goalert/test/smoke/harness"
)

// TestManualEscalation ensures that second step notifications are sent out when an acknowledged alert is manually escalated.
// When an acknowledged alert is manually escalated, it should escalate and go back to the 'unacknowleged' state.
// TestManualEscalation should create an alert in the acknowledged/active state, with a 2+ step EP, then trigger an escalation. Assert that the second step notifications are sent

func TestManualEscalation(t *testing.T) {
	t.Parallel()
	sql := `
	insert into users (id, name, email) 
	values 
		({{uuid "uid"}}, 'bob', 'joe'),
		({{uuid "uid2"}}, 'jane', 'xyz');
	insert into user_contact_methods (id, user_id, name, type, value) 
	values
		({{uuid "c1"}}, {{uuid "uid"}}, 'personal', 'SMS', {{phone "1"}}),
		({{uuid "c2"}}, {{uuid "uid2"}}, 'personal', 'SMS', {{phone "2"}});

	insert into user_notification_rules (user_id, contact_method_id, delay_minutes) 
	values
		({{uuid "uid"}}, {{uuid "c1"}}, 0),
		({{uuid "uid2"}}, {{uuid "c2"}}, 0);
	
	insert into escalation_policies (id, name, repeat, organization_id)
	values 
		({{uuid "eid"}}, 'esc policy', -1, {{smokeOrganizationID}});
	insert into escalation_policy_steps (id, escalation_policy_id, delay) 
	values 
		({{uuid "esid1"}}, {{uuid "eid"}}, 60),
		({{uuid "esid2"}}, {{uuid "eid"}}, 60);

	insert into escalation_policy_actions (escalation_policy_step_id, user_id) 
	values 
		({{uuid "esid1"}}, {{uuid "uid"}}),
		({{uuid "esid2"}}, {{uuid "uid2"}});

	insert into services (id, escalation_policy_id, name, organization_id)
	values
		({{uuid "sid"}}, {{uuid "eid"}}, 'service', {{smokeOrganizationID}});

	insert into alerts (service_id, summary, status, dedup_key)
	values
		({{uuid "sid"}}, 'testing', 'active', 'auto:1:smoke:manualescalationnotification_test:1:1');

	update escalation_policy_state
	set escalation_policy_step_id = {{uuid "esid1"}},
		escalation_policy_step_number = 0,
		last_escalation = now(),
		next_escalation = now() + '1 hour'::interval
	where alert_id = 1;
`

	h := harness.NewHarness(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1")
	defer h.Close()

	h.Twilio(t).WaitAndAssert() // phone 2 should not get SMS before escalating
	h.Escalate(1, 0)

	h.Twilio(t).Device(h.Phone("2")).ExpectSMS("testing")
}
