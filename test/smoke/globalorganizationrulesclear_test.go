package smoke

// Permanent signed HTTP/PG regression distilled from the G1 historical-clear control.
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
)

func TestGlobalOrganizationHistoricalForeignRulesClear(t *testing.T) {
	f := globalOrganizationFixture(t)
	query := `mutation($input:SetScheduleOnCallNotificationRulesInput!){setScheduleOnCallNotificationRules(input:$input)}`
	vars := func(id string, rules []any) any {
		return map[string]any{"input": map[string]any{"scheduleID": id, "rules": rules}}
	}
	rule := map[string]any{"dest": map[string]any{"type": "builtin-webhook", "args": map[string]string{"webhook_url": f.h.URL() + "/g1-synthetic-unused"}}, "time": "12:00", "weekdayFilter": []bool{true, true, true, true, true, true, true}}
	// The two nonempty sets are legally written by the actual Home OrgAdmins.
	for _, row := range []struct{ actor, org string }{{"oa", "a"}, {"ba", "b"}} {
		require.Empty(t, a12Call(t, f, "G1-legal-Home-nonempty", row.actor, query, vars(f.h.UUID("sched-"+row.org), []any{rule})).Errors)
	}
	require.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM notification_channels`))
	b := s2Scalar(t, f, `SELECT data::text FROM schedule_data WHERE schedule_id=$1`, f.h.UUID("sched-b"))
	require.Contains(t, b, "ChannelID")
	// Historical C uses the same global channel, with its own valid rule ID.
	s2Exec(t, f, `INSERT INTO organizations(id,classification,display_name,canonical_name) VALUES($1,'NORMAL','Synthetic c','g1.c')`, f.h.UUID("g1-org-c"))
	s2Exec(t, f, `INSERT INTO normal_organizations(organization_id,organization_classification,corporate_mapping_key,iana_time_zone) VALUES($1,'NORMAL','g1:c','Asia/Shanghai')`, f.h.UUID("g1-org-c"))
	s2Exec(t, f, `INSERT INTO schedules(id,organization_id,name,time_zone) VALUES($1,$2,'G1 Schedule c','Asia/Shanghai')`, f.h.UUID("g1-sched-c"), f.h.UUID("g1-org-c"))
	s2Exec(t, f, `INSERT INTO schedule_data(schedule_id,data) SELECT $1::uuid,replace(data::text,$2::text,$1::text)::jsonb FROM schedule_data WHERE schedule_id=$2::uuid`, f.h.UUID("g1-sched-c"), f.h.UUID("sched-b"))
	initial := a12BusinessSnapshot(t, f)
	sentinels := s2Rows(t, f, `SELECT * FROM schedule_data WHERE schedule_id<>$1`, f.h.UUID("sched-b"))
	restore := func() {
		s2Exec(t, f, `UPDATE schedule_data SET data=$2::jsonb WHERE schedule_id=$1`, f.h.UUID("sched-b"), b)
	}
	for _, actor := range []string{"oa", "om", "od"} {
		before := a12BusinessSnapshot(t, f)
		require.NotEmpty(t, a12Call(t, f, "G1-ordinary-Foreign-clear-denied", actor, query, vars(f.h.UUID("sched-b"), []any{})).Errors)
		require.Equal(t, before, a12BusinessSnapshot(t, f))
	}
	for _, actor := range []string{"pam", "paa", "pd0", "pdm"} {
		t.Run(actor, func(t *testing.T) {
			restore()
			before := a12BusinessSnapshot(t, f)
			require.Empty(t, a12Call(t, f, "G1-historical-nonempty-Foreign-clear", actor, query, vars(f.h.UUID("sched-b"), []any{})).Errors)
			require.Equal(t, "0", s2Scalar(t, f, `SELECT jsonb_array_length(data->'V1'->'OnCallNotificationRules')::text FROM schedule_data WHERE schedule_id=$1`, f.h.UUID("sched-b")))
			after := a12BusinessSnapshot(t, f)
			before["schedule_data"] = after["schedule_data"]
			require.Equal(t, before, after)
			require.Equal(t, s2Scalar(t, f, `SELECT data::text FROM schedule_data WHERE schedule_id=$1`, f.h.UUID("sched-a")), s2Scalar(t, f, `SELECT replace(data::text,$1::text,$2::text) FROM schedule_data WHERE schedule_id=$1::uuid`, f.h.UUID("g1-sched-c"), f.h.UUID("sched-a")))
			stable := a12BusinessSnapshot(t, f)
			require.Empty(t, a12Call(t, f, "G1-repeat-clear", actor, query, vars(f.h.UUID("sched-b"), []any{})).Errors)
			require.Equal(t, stable, a12BusinessSnapshot(t, f))
			require.Equal(t, sentinels, s2Rows(t, f, `SELECT * FROM schedule_data WHERE schedule_id<>$1`, f.h.UUID("sched-b")))
			require.Equal(t, initial["notification_channels"], a12BusinessSnapshot(t, f)["notification_channels"])
			for _, typ := range []string{"builtin-webhook", "builtin-slack-channel", "builtin-user"} {
				denied := map[string]any{"dest": map[string]any{"type": typ, "args": map[string]string{"g1-invalid": "must-not-map"}}}
				r := a12Call(t, f, "G1-Foreign-nonempty-before-channel-mapping", actor, query, vars(f.h.UUID("sched-b"), []any{denied}))
				require.NotEmpty(t, r.Errors)
				require.Contains(t, string(r.Raw), "ownership policy is not defined")
				require.Equal(t, stable, a12BusinessSnapshot(t, f))
				require.Equal(t, sentinels, s2Rows(t, f, `SELECT * FROM schedule_data WHERE schedule_id<>$1`, f.h.UUID("sched-b")))
			}
		})
	}
	restore()
	before := a12BusinessSnapshot(t, f)
	s2Exec(t, f, `CREATE FUNCTION regression_fail_clear() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic G1 clear failure'; END $$`)
	s2Exec(t, f, fmt.Sprintf(`CREATE TRIGGER regression_fail_clear BEFORE UPDATE ON schedule_data FOR EACH ROW WHEN (OLD.schedule_id='%s') EXECUTE FUNCTION regression_fail_clear()`, f.h.UUID("sched-b")))
	f.h.IgnoreErrorsWith("synthetic G1 clear failure")
	require.NotEmpty(t, a12Call(t, f, "G1-clear-persistence-failure", "pd0", query, vars(f.h.UUID("sched-b"), []any{})).Errors)
	require.Equal(t, before, a12BusinessSnapshot(t, f))
	s2Exec(t, f, `DROP TRIGGER regression_fail_clear ON schedule_data; DROP FUNCTION regression_fail_clear()`)

	t.Run("signed-HTTP-cancellation", func(t *testing.T) {
		f.h.IgnoreErrorsWith("context canceled")
		f.h.IgnoreErrorsWith("canceling statement due to user request")
		f.h.IgnoreErrorsWith("conn closed")
		lock, err := f.h.App().DB().BeginTx(t.Context(), nil)
		require.NoError(t, err)
		defer lock.Rollback()
		_, err = lock.ExecContext(t.Context(), `SELECT 1 FROM schedule_data WHERE schedule_id=$1 FOR UPDATE`, f.h.UUID("sched-b"))
		require.NoError(t, err)
		body, err := json.Marshal(map[string]any{"query": query, "variables": vars(f.h.UUID("sched-b"), []any{})})
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.h.URL()+"/api/graphql", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: f.tokens["pd0"]})
		result := make(chan error, 1)
		go func() {
			resp, e := (&http.Client{Timeout: 15 * time.Second}).Do(req)
			if resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			result <- e
		}()
		require.Eventually(t, func() bool {
			return s2Scalar(t, f, `SELECT count(*)::text FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query ILIKE '%schedule_data%'`) != "0"
		}, 5*time.Second, 20*time.Millisecond)
		cancel()
		select {
		case err = <-result:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(5 * time.Second):
			t.Fatal("signed request cancellation did not return")
		}
		require.NoError(t, lock.Rollback())
		require.Eventually(t, func() bool {
			return s2Scalar(t, f, `SELECT count(*)::text FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query ILIKE '%schedule_data%'`) == "0"
		}, 5*time.Second, 20*time.Millisecond)
		require.Equal(t, before, a12BusinessSnapshot(t, f))
		s2Save(t, "G1-real-HTTP-cancellation", map[string]any{"request": map[string]any{"method": "POST", "path": "/api/graphql", "query": query, "variables": vars(f.h.UUID("sched-b"), []any{})}, "signed_actor": "pd0", "observed_PG_lock_wait": true, "transport_result": "context.Canceled; no HTTP response", "business_before": before, "business_after": a12BusinessSnapshot(t, f)})
	})
}
