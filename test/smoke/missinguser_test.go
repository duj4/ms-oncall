package smoke

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/target/goalert/test/smoke/harness"
)

// TestMissingUser tests that notifications go out, even when data is in an odd state.
//
// - escalation policy with no steps
// - escalation policy with steps missing actions
// - policy step with schedule and no users
// - policy step with schedule that starts in the future
func TestMissingUser(t *testing.T) {
	t.Parallel()

	const sql = `
	insert into users (id, name, email)
	values
		({{uuid "u1"}}, 'bob', 'joe'),
		({{uuid "u2"}}, 'ben', 'frank');

	insert into user_contact_methods (id, user_id, name, type, value)
	values
		({{uuid "c1"}}, {{uuid "u1"}}, 'personal', 'SMS', {{phone "1"}}),
		({{uuid "c2"}}, {{uuid "u2"}}, 'personal', 'SMS', {{phone "2"}});

	insert into user_notification_rules (user_id, contact_method_id, delay_minutes)
	values
		({{uuid "u1"}}, {{uuid "c1"}}, 0),
		({{uuid "u2"}}, {{uuid "c2"}}, 0);

	insert into schedules (id, name, time_zone, organization_id)
	values
		({{uuid "empty_sched"}}, 'empty', 'America/Chicago', {{smokeOrganizationID}}),
		({{uuid "empty_rot_sched"}}, 'empty rot', 'America/Chicago', {{smokeOrganizationID}}),
		({{uuid "future_sched"}}, 'future', 'America/Chicago', {{smokeOrganizationID}});
	
	insert into rotations (id, name, type, start_time, shift_length, time_zone, organization_id)
	values
		({{uuid "empty_rot"}}, 'empty rotation', 'daily', now() - '1 hour'::interval, 1, 'America/Chicago', {{smokeOrganizationID}}),
		({{uuid "future_rot"}}, 'future rotation', 'daily', now() + '1 hour'::interval, 1, 'America/Chicago', {{smokeOrganizationID}});

	insert into schedule_rules (schedule_id, tgt_rotation_id)
	values
		({{uuid "empty_rot_sched"}}, {{uuid "empty_rot"}});
	
	insert into rotation_participants (id, rotation_id, position, user_id)
	values
		({{uuid ""}}, {{uuid "future_rot"}}, 0, {{uuid "u1"}});

	insert into escalation_policies (id, name, organization_id)
	values
		({{uuid "empty_policy"}}, 'esc policy', {{smokeOrganizationID}}),
		({{uuid "empty_step"}}, 'empty step', {{smokeOrganizationID}}),
		({{uuid "empty_sched_pol"}}, 'empty sched', {{smokeOrganizationID}}),
		({{uuid "empty_rot_pol"}}, 'empty rot', {{smokeOrganizationID}}),
		({{uuid "future_sched_pol"}}, 'future', {{smokeOrganizationID}}),
		({{uuid "tech.correct"}}, 'woot', {{smokeOrganizationID}});

	insert into escalation_policy_steps (id, escalation_policy_id)
	values
		({{uuid ""}}, {{uuid "empty_step"}}),
		({{uuid "empty_sched_step"}}, {{uuid "empty_sched_pol"}}),
		({{uuid "empty_rot_step"}}, {{uuid "empty_rot_pol"}}),
		({{uuid "future_sched_step"}}, {{uuid "future_sched_pol"}}),
		({{uuid "tech.correct_step"}}, {{uuid "tech.correct"}});

	insert into escalation_policy_actions (escalation_policy_step_id, user_id, schedule_id)
	values
		({{uuid "empty_sched_step"}}, null, {{uuid "empty_sched"}}),
		({{uuid "empty_rot_step"}}, null, {{uuid "empty_rot_sched"}}),
		({{uuid "future_sched_step"}}, null, {{uuid "future_sched"}}),
		({{uuid "tech.correct_step"}}, null, {{uuid "empty_sched"}}),
		({{uuid "tech.correct_step"}}, {{uuid "u1"}}, null);

	insert into services (id, escalation_policy_id, name, organization_id)
	values
		({{uuid "s1"}}, {{uuid "empty_policy"}}, 'service1', {{smokeOrganizationID}}),
		({{uuid "s2"}}, {{uuid "empty_step"}}, 'service2', {{smokeOrganizationID}}),
		({{uuid "s3"}}, {{uuid "empty_sched_pol"}}, 'service3', {{smokeOrganizationID}}),
		({{uuid "s4"}}, {{uuid "future_sched_pol"}}, 'service4', {{smokeOrganizationID}}),
		({{uuid "s5"}}, {{uuid "tech.correct"}}, 'service5', {{smokeOrganizationID}}),
		({{uuid "s6"}}, {{uuid "empty_rot_pol"}}, 'service6', {{smokeOrganizationID}});

	insert into alerts (service_id, summary, dedup_key)
	values
		({{uuid "s1"}}, 'emptypol', 'auto:1:smoke:missinguser_test:1:1'),
		({{uuid "s2"}}, 'emptystep', 'auto:1:smoke:missinguser_test:1:2'),
		({{uuid "s3"}}, 'emptysched', 'auto:1:smoke:missinguser_test:1:3'),
		({{uuid "s4"}}, 'futuresched', 'auto:1:smoke:missinguser_test:1:4'),
		({{uuid "s5"}}, 'correct', 'auto:1:smoke:missinguser_test:1:5'),
		({{uuid "s6"}}, 'emptyrot', 'auto:1:smoke:missinguser_test:1:6');

`
	h := harness.NewHarness(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1")
	defer h.Close()

	d := h.Twilio(t).Device(h.Phone("1"))
	err := h.EscalateAlertErr(1)
	assert.Error(t, err, "empty policy")
	d.ExpectSMS("correct")

	// Rotations will always have someone active, as long as there are 1 or more participants
}
