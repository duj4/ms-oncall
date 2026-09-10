package smoke

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"

	"github.com/target/goalert/test/smoke/harness"
)

// TestStatusUpdates checks basic functionality of status updates:
//
// - If alert_status_log_contact_method_id isnull, no notifications are sent
// - When alert_status_log_contact_method_id is set, old notifications are NOT sent
// - Status changes, when/after alert_status_log_contact_method_id is set, are sent.
func TestStatusUpdates(t *testing.T) {
	t.Parallel()

	sql := `
	insert into users (id, name, email, role) 
	values 
		({{uuid "user"}}, 'bob', 'joe@test.com', 'admin');
	insert into user_contact_methods (id, user_id, name, type, value, enable_status_updates)
	values
		({{uuid "cm1"}}, {{uuid "user"}}, 'personal', 'SMS', {{phone "1"}}, true);

	update users set alert_status_log_contact_method_id = {{uuid "cm1"}}
	where id = {{uuid "user"}};

	insert into user_notification_rules (user_id, contact_method_id, delay_minutes) 
	values
		({{uuid "user"}}, {{uuid "cm1"}}, 0);

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

	insert into integration_keys (id, service_id, type, name)
	values
		({{uuid "int1"}}, {{uuid "sid"}}, 'generic', 'test');

	insert into alerts (service_id, source, summary, dedup_key)
	values
		({{uuid "sid"}}, 'manual', 'first alert', 'auto:1:32dfcc759fb0856b4e36d72cfd057c675d9be3ff406a44127ce3f8d2b7316a4fbf0003fcc7cd9dc897d208cde753a4cd30026385ddbf3f5d854f8344f07517b8'),
		({{uuid "sid"}}, 'manual', 'second alert', 'auto:1:aa540e455c92e596f8398bcf99bee1495b8d1ba9cfa4f74ce2a3410c11f5dac92aeb55d45ec321618f74c7d5fb2f5ef5c4a22c757e3a5de3d5dc707b9a20888e');

`
	h := harness.NewHarness(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1")
	defer h.Close()

	doClose := func(summary string) {
		u := h.URL() + "/v1/api/alerts?key=" + h.UUID("int1")
		v := make(url.Values)
		v.Set("summary", summary)
		v.Set("action", "close")
		resp, err := http.Post(u, "application/x-www-form-urlencoded", bytes.NewBufferString(v.Encode()))
		if err != nil {
			t.Fatal("post to generic endpoint failed:", err)
		} else if resp.StatusCode/100 != 2 {
			t.Error("non-2xx response:", resp.Status)
		}
		resp.Body.Close()
	}

	tw := h.Twilio(t)
	d1 := tw.Device(h.Phone("1"))

	d1.ExpectSMS("first alert")
	d1.ExpectSMS("second alert")

	doClose("first alert")
	d1.ExpectSMS("closed")

	doClose("second alert")
	d1.ExpectSMS("closed")

	// Ensure status updates are not sent to the user that caused them.
	h.CreateAlert(h.UUID("sid"), "third alert")
	d1.ExpectSMS("third alert").ThenReply("c").ThenExpect("closed")
}
