package smoke

import (
	"fmt"
	"testing"
	"time"

	"github.com/target/goalert/test/smoke/harness"
)

// TestGraphQLDedup tests that creating and closing an alert with a dedup key works.
func TestGraphQLDedup(t *testing.T) {
	t.Parallel()

	sql := `
	insert into users (id, name, email) 
	values 
		({{uuid "user"}}, 'bob', 'joe');
	insert into user_contact_methods (id, user_id, name, type, value) 
	values
		({{uuid "cm"}}, {{uuid "user"}}, 'personal', 'SMS', {{phone "1"}});

	insert into user_notification_rules (user_id, contact_method_id, delay_minutes) 
	values
		({{uuid "user"}}, {{uuid "cm"}}, 0);

	insert into escalation_policies (id, name, repeat, organization_id)
	values
		({{uuid "eid"}}, 'esc policy', 5, {{smokeOrganizationID}});
	insert into escalation_policy_steps (id, escalation_policy_id, delay) 
	values
		({{uuid "esid"}}, {{uuid "eid"}}, 10);
	insert into escalation_policy_actions (escalation_policy_step_id, user_id) 
	values 
		({{uuid "esid"}}, {{uuid "user"}});

	insert into services (id, escalation_policy_id, name, organization_id)
	values
		({{uuid "sid"}}, {{uuid "eid"}}, 'service', {{smokeOrganizationID}});
`

	h := harness.NewHarness(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1")
	defer h.Close()

	doQL := func(query string) {
		g := h.GraphQLQuery2(query)
		for _, err := range g.Errors {
			t.Error("GraphQL Error:", err.Message)
		}
		if len(g.Errors) > 0 {
			t.Fatal("errors returned from GraphQL")
		}
		t.Log("Response:", string(g.Data))
	}

	doQL(fmt.Sprintf(`mutation{createAlert(input: {summary: "foo", serviceID: "%s", dedup: "somekey1"}){id}}`, h.UUID("sid")))

	h.Twilio(t).Device(h.Phone("1")).ExpectSMS("foo")

	h.FastForward(10 * time.Minute)

	h.Twilio(t).Device(h.Phone("1")).ExpectSMS("foo")

	doQL(fmt.Sprintf(`mutation{closeMatchingAlert(input:{serviceID: "%s", dedup:"somekey1"})}`, h.UUID("sid")))

	h.FastForward(10 * time.Minute)

	// no new sms
}
