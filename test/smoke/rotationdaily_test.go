package smoke

import (
	"testing"
	"time"

	"github.com/target/goalert/test/smoke/harness"
)

func TestRotation_Daily(t *testing.T) {
	t.Parallel()

	const sql = `
	insert into users (id, name, email)
	values
		({{uuid "uid1"}}, 'bob', 'joe'),
		({{uuid "uid2"}}, 'ben', 'frank');

	insert into user_contact_methods (id, user_id, name, type, value)
	values
		({{uuid "cm1"}}, {{uuid "uid1"}}, 'personal', 'SMS', {{phone "1"}}),
		({{uuid "cm2"}}, {{uuid "uid2"}}, 'personal', 'SMS', {{phone "2"}});

	insert into user_notification_rules (user_id, contact_method_id, delay_minutes)
	values
		({{uuid "uid1"}}, {{uuid "cm1"}}, 0),
		({{uuid "uid2"}}, {{uuid "cm2"}}, 0);

	insert into escalation_policies (id, name, repeat, organization_id)
	values
		({{uuid "eid"}}, 'esc policy', 1, {{smokeOrganizationID}});

	insert into escalation_policy_steps (id, escalation_policy_id, delay)
	values
		({{uuid "es1"}}, {{uuid "eid"}}, 60);

	insert into schedules (id, name, time_zone, organization_id)
	values
		({{uuid "sched1"}}, 'default', 'America/Chicago', {{smokeOrganizationID}});

	insert into rotations (id, name, type, start_time, shift_length, time_zone, organization_id)
	values
		({{uuid "rot1"}}, 'default rotation', 'daily', now(), 2, 'America/Chicago', {{smokeOrganizationID}});

	insert into schedule_rules (schedule_id, tgt_rotation_id)
	values
		({{uuid "sched1"}}, {{uuid "rot1"}});

	insert into rotation_participants (rotation_id, user_id, position)
	values
		({{uuid "rot1"}}, {{uuid "uid1"}}, 0),
		({{uuid "rot1"}}, {{uuid "uid2"}}, 1);

	insert into escalation_policy_actions (escalation_policy_step_id, schedule_id)
	values
		({{uuid "es1"}}, {{uuid "sched1"}});

	insert into services (id, escalation_policy_id, name, organization_id) values
		({{uuid "sid"}}, {{uuid "eid"}}, 'service', {{smokeOrganizationID}});
	`
	h := harness.NewHarness(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1")
	defer h.Close()

	sid := h.UUID("sid")
	uid1 := h.UUID("uid1")
	uid2 := h.UUID("uid2")

	h.WaitAndAssertOnCallUsers(sid, uid1)

	// Skipping ahead by an extra day to jump over DST changes.
	//
	// In the spring, one shift will be an hour short.
	// In the fall, one shift will be an hour long.
	h.FastForward(3 * 24 * time.Hour)

	h.WaitAndAssertOnCallUsers(sid, uid2)
}
