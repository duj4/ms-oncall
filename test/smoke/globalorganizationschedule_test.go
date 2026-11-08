package smoke

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGlobalOrganizationForeignTemporarySchedule(t *testing.T) {
	f := globalOrganizationFixture(t)
	start := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	end := start.Add(time.Hour)
	input := map[string]any{"scheduleID": f.h.UUID("sched-b"), "start": start, "end": end, "shifts": []any{map[string]any{"userID": f.h.UUID("b"), "start": start, "end": end}}}
	set := `mutation($input:SetTemporaryScheduleInput!){setTemporarySchedule(input:$input)}`
	clear := `mutation($input:ClearTemporarySchedulesInput!){clearTemporarySchedules(input:$input)}`
	for _, actor := range []string{"pam", "paa", "pd0", "pdm", "oa", "om", "od"} {
		t.Run(actor, func(t *testing.T) {
			before := a12BusinessSnapshot(t, f)
			r := a12Call(t, f, "foreign-temporary-set", actor, set, map[string]any{"input": input})
			pa := actor == "pam" || actor == "paa" || actor == "pd0" || actor == "pdm"
			if !pa {
				if actor == "oa" {
					require.NotEmpty(t, r.Errors)
					require.Contains(t, string(r.Raw), "schedule does not exist")
					require.Contains(t, string(r.Raw), "isFieldError")
				} else {
					s2Deny(t, r)
				}
				require.Equal(t, before, a12BusinessSnapshot(t, f))
				return
			}
			require.Empty(t, r.Errors)
			r = a12Call(t, f, "read-temporary-actual-participant", actor, fmt.Sprintf(`{schedule(id:%q){temporarySchedules{start end shifts{userID user{id name}}}}}`, f.h.UUID("sched-b")), nil)
			require.Empty(t, r.Errors)
			require.Contains(t, string(r.Raw), f.h.UUID("b"))
			require.NotContains(t, string(r.Raw), f.h.UUID(actor))
			r = a12Call(t, f, "foreign-temporary-clear", actor, clear, map[string]any{"input": map[string]any{"scheduleID": f.h.UUID("sched-b"), "start": start, "end": end}})
			require.Empty(t, r.Errors)
			after := a12BusinessSnapshot(t, f)
			before["schedule_data"] = after["schedule_data"]
			require.Equal(t, before, after, "temporary configuration changed unrelated business state")
		})
	}
	for _, actor := range []string{"pam", "pd0"} {
		for _, bad := range []string{"foreign-user", "invalid-range", "clear-and-set-rollback"} {
			t.Run(actor+"/"+bad, func(t *testing.T) {
				copy := map[string]any{}
				for k, v := range input {
					copy[k] = v
				}
				if bad == "invalid-range" {
					copy["end"] = start.Add(-time.Hour)
				} else {
					copy["shifts"] = []any{map[string]any{"userID": f.h.UUID(actor), "start": start, "end": end}}
				}
				if bad == "clear-and-set-rollback" {
					copy["clearStart"] = start
					copy["clearEnd"] = end
				}
				before := a12BusinessSnapshot(t, f)
				r := a12Call(t, f, bad, actor, set, map[string]any{"input": copy})
				require.NotEmpty(t, r.Errors)
				require.Equal(t, before, a12BusinessSnapshot(t, f))
			})
		}
	}
}

func TestGlobalOrganizationForeignNotificationPolicyBoundary(t *testing.T) {
	f := globalOrganizationFixture(t)
	query := `mutation($input:SetScheduleOnCallNotificationRulesInput!){setScheduleOnCallNotificationRules(input:$input)}`
	for _, actor := range []string{"pam", "pd0", "pdm", "oa", "om", "od"} {
		t.Run(actor, func(t *testing.T) {
			before := a12BusinessSnapshot(t, f)
			r := a12Call(t, f, "Foreign-notification-clear", actor, query, map[string]any{"input": map[string]any{"scheduleID": f.h.UUID("sched-b"), "rules": []any{}}})
			pa := actor == "pam" || actor == "pd0" || actor == "pdm"
			if !pa {
				if actor == "oa" {
					require.NotEmpty(t, r.Errors)
					require.Contains(t, string(r.Raw), "schedule does not exist")
					require.Contains(t, string(r.Raw), "isFieldError")
				} else {
					s2Deny(t, r)
				}
				require.Equal(t, before, a12BusinessSnapshot(t, f))
				return
			}
			require.Empty(t, r.Errors)
			before = a12BusinessSnapshot(t, f)
			for _, typ := range []string{"builtin-webhook", "builtin-slack-channel", "builtin-user"} {
				r = a12Call(t, f, "Foreign-destination-ownership-gap", actor, query, map[string]any{"input": map[string]any{"scheduleID": f.h.UUID("sched-b"), "rules": []any{map[string]any{"dest": map[string]any{"type": typ, "args": map[string]string{}}}}}})
				require.NotEmpty(t, r.Errors)
				require.Contains(t, string(r.Raw), "ownership policy is not defined")
				require.Equal(t, before, a12BusinessSnapshot(t, f))
			}
		})
	}
}

func TestGlobalOrganizationHomeNotificationCompatibility(t *testing.T) {
	f := globalOrganizationFixture(t)
	q := `mutation($input:SetScheduleOnCallNotificationRulesInput!){setScheduleOnCallNotificationRules(input:$input)}`
	for _, actor := range []string{"oa", "pam"} {
		t.Run(actor, func(t *testing.T) {
			rule := map[string]any{"dest": map[string]any{"type": "builtin-webhook", "args": map[string]string{"webhook_url": f.h.URL() + "/a12-synthetic-local-unused"}}, "time": "12:00", "weekdayFilter": []bool{true, true, true, true, true, true, true}}
			input := map[string]any{"scheduleID": f.h.UUID("sched-a"), "rules": []any{rule}}
			r := a12Call(t, f, "Home-notification-positive", actor, q, map[string]any{"input": input})
			require.Empty(t, r.Errors)
			before := a12BusinessSnapshot(t, f)
			input["rules"] = []any{rule, rule}
			r = a12Call(t, f, "Home-duplicate-preserves-set", actor, q, map[string]any{"input": input})
			require.NotEmpty(t, r.Errors)
			require.Equal(t, before, a12BusinessSnapshot(t, f))
			input["rules"] = []any{rule, map[string]any{"dest": map[string]any{"type": "builtin-user", "args": map[string]string{"user_id": f.h.UUID("aowner")}}}}
			r = a12Call(t, f, "Home-invalid-destination-preserves-set", actor, q, map[string]any{"input": input})
			require.NotEmpty(t, r.Errors)
			require.Equal(t, before, a12BusinessSnapshot(t, f))
			input["rules"] = []any{}
			require.Empty(t, a12Call(t, f, "Home-notification-clear", actor, q, map[string]any{"input": input}).Errors)
		})
	}
}
