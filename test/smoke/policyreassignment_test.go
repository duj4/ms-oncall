package smoke

import (
	"fmt"
	"testing"
	"time"

	"github.com/target/goalert/test/smoke/harness"
)

// TestPolicyReassignment tests that only the active escalation policy is used for alerts.
func TestPolicyReassignment(t *testing.T) {
	t.Parallel()

	const sql = `
insert into users (id, name, email)
values
	({{uuid "user"}}, 'bob', 'joe'),
	({{uuid "user2"}}, 'bob2', 'joe2');

insert into user_contact_methods (id, user_id, name, type, value)
values
	({{uuid "cm1"}}, {{uuid "user"}}, 'personal', 'SMS', {{phone "1"}}),
	({{uuid "cm2"}}, {{uuid "user2"}}, 'personal', 'SMS', {{phone "2"}});

insert into user_notification_rules (user_id, contact_method_id, delay_minutes)
values
	({{uuid "user"}}, {{uuid "cm1"}}, 0),
	({{uuid "user2"}}, {{uuid "cm2"}}, 0);

insert into escalation_policies (id, name, organization_id)
values
	({{uuid "ep1"}}, 'esc policy 1', {{smokeOrganizationID}}),
	({{uuid "ep2"}}, 'esc policy 2', {{smokeOrganizationID}});

insert into escalation_policy_steps (id, escalation_policy_id, delay)
values
	({{uuid "ep1_1"}}, {{uuid "ep1"}}, 30),
	({{uuid "ep1_2"}}, {{uuid "ep1"}}, 60),
	({{uuid "ep2_1"}}, {{uuid "ep2"}}, 60);
	
insert into escalation_policy_actions (escalation_policy_step_id, user_id) 
values
	({{uuid "ep1_1"}}, {{uuid "user"}}),
	({{uuid "ep1_2"}}, {{uuid "user"}}),
	({{uuid "ep2_1"}}, {{uuid "user2"}});

insert into services (id, escalation_policy_id, name, organization_id)
values
    ({{uuid "sid"}}, {{uuid "ep1"}}, 'service', {{smokeOrganizationID}});

insert into alerts (service_id, summary, dedup_key)
values
    ({{uuid "sid"}}, 'testing', 'auto:1:smoke:policyreassignment_test:1:1');

`
	h := harness.NewHarness(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1")
	defer h.Close()

	tw := h.Twilio(t)
	d1 := tw.Device(h.Phone("1"))
	d2 := tw.Device(h.Phone("2"))

	d1.ExpectSMS("testing")

	h.GraphQLQuery2(fmt.Sprintf(`
		mutation{
			updateService(input:{
				id: "%s"
				name: "ok"
				escalationPolicyID: "%s"
			})
		}
	`, h.UUID("sid"), h.UUID("ep2")))

	d2.ExpectSMS("testing")

	h.FastForward(30 * time.Minute)
	// no new alerts
	tw.WaitAndAssert()

	h.GraphQLQuery2(fmt.Sprintf(`
		mutation{
		updateService(input:{
			id: "%s"
			name: "ok"
			escalationPolicyID: "%s"
		}) 
		}
	`, h.UUID("sid"), h.UUID("ep1")))

	// should get immediate message
	d1.ExpectSMS("testing")
}
