package smoke

import (
	"testing"

	"github.com/target/goalert/test/smoke/harness"
)

// TestNCDedup tests that deduplicated notification_channels continue to function in schedule_data.
func TestNCDedup(t *testing.T) {
	t.Parallel()

	const sql = `
	insert into users (id, name, email) values
		({{uuid "uid"}}, 'bob', '');

	insert into schedules (id, name, time_zone, organization_id) values
		({{uuid "sched1"}}, 'schedule 1', 'UTC', {{smokeOrganizationID}}),
		({{uuid "sched2"}}, 'schedule 2', 'UTC', {{smokeOrganizationID}}),
		({{uuid "sched3"}}, 'schedule 3', 'UTC', {{smokeOrganizationID}});
	
	insert into schedule_rules (schedule_id, sunday, monday, tuesday, wednesday, thursday, friday, saturday, start_time, end_time, tgt_user_id) values
		({{uuid "sched1"}}, true, true, true, true, true, true, true, '00:00:00', '00:00:00', {{uuid "uid"}}),
		({{uuid "sched2"}}, true, true, true, true, true, true, true, '00:00:00', '00:00:00', {{uuid "uid"}}),
		({{uuid "sched3"}}, true, true, true, true, true, true, true, '00:00:00', '00:00:00', {{uuid "uid"}});

	insert into notification_channels (id, type, name, value, created_at) values
		({{uuid "nc1"}}, 'SLACK', 'chan 1', {{slackChannelID "chan1"}}, now());


	insert into schedule_data (schedule_id, data) values
		({{uuid "sched1"}}, '{"V1": {"OnCallNotificationRules": [{  "ChannelID": {{uuidJSON "nc1"}} }] } }'),
		({{uuid "sched2"}}, '{"V1": {"OnCallNotificationRules": [{  "ChannelID": {{uuidJSON "nc1"}} }] } }');
	`

	h := harness.NewHarness(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1")
	defer h.Close()

	h.Slack().Channel("chan1").ExpectMessage("on-call")
	h.Slack().Channel("chan1").ExpectMessage("on-call")
}
