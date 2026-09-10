package smoke

import (
	"testing"

	"github.com/target/goalert/test/smoke/harness"
)

// TestStatusInProgress ensures that sent and in-progress notifications for triggered alerts are honored through the migration.
func TestStatusInProgress(t *testing.T) {
	t.Parallel()
	sql := `
		insert into users (id, name, email) 
		values
			({{uuid "u1"}}, 'bob', 'bob@email.com'),
			({{uuid "u2"}}, 'joe', 'joe@email.com');

		insert into user_contact_methods (id, user_id, name, type, value, enable_status_updates)
		values
			({{uuid "c1"}}, {{uuid "u1"}}, 'personal', 'SMS', {{phone "1"}}, true);

		update users
		set alert_status_log_contact_method_id = {{uuid "c1"}}
		where id = {{uuid "u1"}};

		insert into escalation_policies (id, name, repeat, organization_id)
		values
			({{uuid "eid"}}, 'esc policy', -1, {{smokeOrganizationID}});

		insert into services (id, escalation_policy_id, name, organization_id)
		values
			({{uuid "sid"}}, {{uuid "eid"}}, 'service', {{smokeOrganizationID}});

		insert into alerts (id, service_id, status, summary) 
		values
			(1, {{uuid "sid"}}, 'closed', 'test');

		insert into alert_logs (id, alert_id, event, sub_user_id, sub_type, message)
		values
			(100, 1, 'created', null, null,''),
			(101, 1, 'notification_sent', {{uuid "u1"}}, 'user', ''),
			(102, 1, 'acknowledged', {{uuid "u2"}}, 'user', ''),
			(103, 1, 'closed', {{uuid "u2"}}, 'user', '');

		insert into alert_status_subscriptions (contact_method_id, alert_id, last_alert_status)
		values
			({{uuid "c1"}}, 1, 'active');

		insert into outgoing_messages(message_type, user_id, contact_method_id, alert_id, service_id, escalation_policy_id, last_status, sent_at)
		values
			('alert_notification', {{uuid "u1"}}, {{uuid "c1"}}, 1, {{uuid "sid"}}, {{uuid "eid"}}, 'delivered', now());
	`

	h := harness.NewHarness(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1")
	defer h.Close()

	tw := h.Twilio(t)
	d1 := tw.Device(h.Phone("1"))

	d1.ExpectSMS("Closed", "joe")
}
