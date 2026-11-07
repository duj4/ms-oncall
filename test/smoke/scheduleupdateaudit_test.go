package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/test/smoke/harness"
)

const scheduleUpdateAuditSQL = servicePlatformAdminSQL + `
INSERT INTO schedules(id,organization_id,name,time_zone) VALUES
 ({{uuid "schedule-a"}},{{smokeOrganizationID}},'Schedule A','Etc/UTC'),
 ({{uuid "schedule-b"}},{{uuid "org-b"}},'Schedule B','Etc/UTC'),
 ({{uuid "schedule-c"}},{{smokeOrganizationID}},'Schedule C','Etc/UTC');`

func scheduleAuditHarness(t *testing.T) *harness.Harness {
	t.Helper()
	h := harness.NewHarness(t, scheduleUpdateAuditSQL, "")
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	return h
}

func scheduleAuditCount(t *testing.T, h *harness.Harness) int {
	t.Helper()
	var n int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM schedule_rotation_update_audit_events`).Scan(&n))
	return n
}

func scheduleAuditRows(t *testing.T, h *harness.Harness) string {
	t.Helper()
	var rows, dbName, version, schedules string
	require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY occurred_at,event_id),'[]')::text FROM schedule_rotation_update_audit_events e`).Scan(&rows))
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database(),current_setting('server_version')`).Scan(&dbName, &version))
	require.NoError(t, h.App().DB().QueryRow(`SELECT jsonb_agg(to_jsonb(s) ORDER BY id)::text FROM schedules s`).Scan(&schedules))
	if dir := os.Getenv("SCHEDULE_UPDATE_AUDIT_EVIDENCE"); dir != "" {
		b, err := json.MarshalIndent(map[string]any{"database": dbName, "postgres_version": version, "events": json.RawMessage(rows), "schedules": json.RawMessage(schedules)}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "-")+".json"), append(b, '\n'), 0600))
	}
	return rows
}

func TestScheduleUpdateAuditSignedHTTPRoles(t *testing.T) {
	h := scheduleAuditHarness(t)
	for _, tc := range []struct {
		role                 string
		pa, foreign, allowed bool
	}{
		{"ORG_MEMBER", true, false, true}, {"ORG_ADMIN", true, false, true}, {"ORG_ADMIN", false, false, true},
		{"ORG_MEMBER", true, true, true}, {"ORG_ADMIN", true, true, true}, {"ORG_ADMIN", false, true, false},
		{"ORG_MEMBER", false, false, false}, {"ORG_MEMBER", false, true, false},
	} {
		ikSetAuthority(t, h, tc.role, tc.pa)
		id := h.UUID("schedule-a")
		if tc.foreign {
			id = h.UUID("schedule-b")
		}
		before := serviceManagementSnapshot(t, h)
		n := scheduleAuditCount(t, h)
		r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateSchedule(input:{id:%q,description:"Synthetic signed HTTP update"})}`, id))
		if tc.allowed {
			require.Empty(t, r.Errors)
		} else {
			require.NotEmpty(t, r.Errors)
			require.Equal(t, before, serviceManagementSnapshot(t, h))
		}
		require.Equal(t, n+1, scheduleAuditCount(t, h))
		var actor, home, role, orgRole, op, source, outcome, reason string
		var target, org sql.NullString
		var mask int
		require.NoError(t, h.App().DB().QueryRow(`SELECT actor_id,home_organization_id,authority_role,organization_role,operation,authority_source,outcome,reason_code,target_id,target_organization_id,requested_fields FROM schedule_rotation_update_audit_events ORDER BY occurred_at DESC LIMIT 1`).Scan(&actor, &home, &role, &orgRole, &op, &source, &outcome, &reason, &target, &org, &mask))
		require.Equal(t, h.UUID("user-a"), actor)
		require.Equal(t, harness.SmokeOrganizationID, home)
		require.Equal(t, tc.role, orgRole)
		require.Equal(t, "schedule.update", op)
		require.Equal(t, "current_local_user_organization_at_admission", source)
		require.Equal(t, 2, mask)
		if tc.pa {
			require.Equal(t, "platform_admin", role)
		} else if tc.role == "ORG_ADMIN" {
			require.Equal(t, "org_admin", role)
		} else {
			require.Equal(t, "org_member", role)
		}
		if tc.allowed {
			require.Equal(t, "committed", outcome)
			require.Equal(t, id, target.String)
			wantOrg := home
			if tc.foreign {
				wantOrg = h.UUID("org-b")
			}
			require.Equal(t, wantOrg, org.String)
			var actualOrg string
			require.NoError(t, h.App().DB().QueryRow(`SELECT organization_id FROM schedules WHERE id=$1`, target.String).Scan(&actualOrg))
			require.Equal(t, actualOrg, org.String)
		} else {
			require.False(t, target.Valid)
			require.False(t, org.Valid, "never infer target from Home/input")
			if tc.pa || tc.role == "ORG_ADMIN" {
				require.Equal(t, "validation_failed", outcome)
				require.Equal(t, "target_unavailable", reason)
			} else {
				require.Equal(t, "denied", outcome)
			}
		}
	}
	scheduleAuditRows(t, h)
}

func TestScheduleUpdateAuditFieldsAndValidation(t *testing.T) {
	h := scheduleAuditHarness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	for _, tc := range []struct {
		fields string
		mask   int
		valid  bool
		field  string
	}{
		{`name:"Changed Schedule",description:"Synthetic description",timeZone:"Asia/Shanghai"`, 7, true, ""},
		{`description:"Partial description"`, 2, true, ""}, {``, 0, true, ""}, {`name:null,description:null,timeZone:null`, 0, true, ""},
		{`name:""`, 1, false, "Name"}, {`name:"",timeZone:"SYNTHETIC_BAD_TIMEZONE"`, 5, false, "timeZone"},
	} {
		before := serviceManagementSnapshot(t, h)
		r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateSchedule(input:{id:%q,%s})}`, h.UUID("schedule-a"), tc.fields))
		if tc.valid {
			require.Empty(t, r.Errors)
		} else {
			require.NotEmpty(t, r.Errors)
			require.Contains(t, fmt.Sprint(r.Errors), tc.field)
			require.Equal(t, before, serviceManagementSnapshot(t, h))
		}
		var mask int
		var target sql.NullString
		require.NoError(t, h.App().DB().QueryRow(`SELECT requested_fields,target_id FROM schedule_rotation_update_audit_events ORDER BY occurred_at DESC LIMIT 1`).Scan(&mask, &target))
		require.Equal(t, tc.mask, mask)
		if tc.field == "timeZone" {
			require.False(t, target.Valid, "TimeZone validation precedes target lookup")
		}
	}
	var name, description, tz string
	require.NoError(t, h.App().DB().QueryRow(`SELECT name,description,time_zone FROM schedules WHERE id=$1`, h.UUID("schedule-a")).Scan(&name, &description, &tz))
	require.Equal(t, "Changed Schedule", name)
	require.Equal(t, "Partial description", description)
	require.Equal(t, "Asia/Shanghai", tz)
	duplicate := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateSchedule(input:{id:%q,name:"Schedule C"})}`, h.UUID("schedule-a")))
	require.NotEmpty(t, duplicate.Errors)
	require.Contains(t, fmt.Sprint(duplicate.Errors), "already in use")
	// Multiple root fields are independent top-level attempts sharing one RequestID.
	r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{a:updateSchedule(input:{id:%q,description:"First root"}) b:updateSchedule(input:{id:%q})}`, h.UUID("schedule-a"), h.UUID("schedule-c")))
	require.Empty(t, r.Errors)
	var attempts, requests int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(DISTINCT attempt_id),count(DISTINCT request_id) FROM (SELECT * FROM schedule_rotation_update_audit_events ORDER BY occurred_at DESC LIMIT 2) e`).Scan(&attempts, &requests))
	require.Equal(t, 2, attempts)
	require.Equal(t, 1, requests)
	before := scheduleAuditCount(t, h)
	bad := serviceAuditHTTP(t, h, `mutation{updateSchedule(input:{name:"Missing locator"})}`, "SYNTHETIC_SCHEMA_HEADER")
	require.Contains(t, bad, `"errors"`)
	require.Equal(t, before, scheduleAuditCount(t, h), "schema errors never enter resolver")
	require.NotContains(t, scheduleAuditRows(t, h), "Synthetic description")
}

func TestScheduleUpdateAuditAdmissionAndInternal(t *testing.T) {
	h := scheduleAuditHarness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	token := h.GraphQLToken(h.UUID("user-a"))
	query := func(id string) *stepOrganizationResponse {
		return stepOrganizationPost(t, h, map[string]any{"query": fmt.Sprintf(`mutation{updateSchedule(input:{id:%q,description:"Current admission"})}`, id)}, token, false)
	}
	require.Empty(t, query(h.UUID("schedule-a")).Errors)
	_, err := h.App().DB().Exec(`UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, h.UUID("user-a"), h.UUID("org-b"))
	require.NoError(t, err)
	require.NotEmpty(t, query(h.UUID("schedule-a")).Errors)
	require.Empty(t, query(h.UUID("schedule-b")).Errors)
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	require.NotEmpty(t, query(h.UUID("schedule-b")).Errors)
	_, err = h.App().DB().Exec(`UPDATE user_organization_assignments SET effective_organization_id=(SELECT id FROM organizations WHERE classification='DEFAULT'),effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, h.UUID("user-a"))
	require.NoError(t, err)
	require.NotEmpty(t, query(h.UUID("schedule-b")).Errors)
	_, err = h.App().DB().Exec(`DELETE FROM user_organization_assignments WHERE user_id=$1`, h.UUID("user-a"))
	require.NoError(t, err)
	require.NotEmpty(t, query(h.UUID("schedule-b")).Errors)
	store, err := schedule.NewStore(context.Background(), h.App().DB(), nil)
	require.NoError(t, err)
	a := graphqlapp.App{DB: h.App().DB(), ScheduleStore: store}
	badRequester, err := auth.NewRequester(uuid.NewString(), uuid.NewString())
	require.NoError(t, err)
	for _, ctx := range []context.Context{context.Background(), permission.UserContext(context.Background(), h.UUID("user-a"), permission.RoleAdmin), auth.WithRequester(permission.SystemContext(context.Background(), "SyntheticConflict"), badRequester)} {
		before := serviceManagementSnapshot(t, h)
		ok, err := a.Mutation().UpdateSchedule(ctx, graphql2.UpdateScheduleInput{ID: h.UUID("schedule-a")})
		require.False(t, ok)
		require.Error(t, err)
		require.Equal(t, before, serviceManagementSnapshot(t, h))
		var actor string
		var target, home sql.NullString
		require.NoError(t, h.App().DB().QueryRow(`SELECT actor_kind,target_id,home_organization_id FROM schedule_rotation_update_audit_events ORDER BY occurred_at DESC LIMIT 1`).Scan(&actor, &target, &home))
		require.Equal(t, "unknown", actor)
		require.False(t, target.Valid)
		require.False(t, home.Valid)
	}
	value := "Synthetic internal update"
	ok, err := a.Mutation().UpdateSchedule(permission.SystemContext(context.Background(), "SyntheticInternal"), graphql2.UpdateScheduleInput{ID: h.UUID("schedule-b"), Description: &value})
	require.NoError(t, err)
	require.True(t, ok)
	var actor, target string
	require.NoError(t, h.App().DB().QueryRow(`SELECT actor_kind,target_organization_id FROM schedule_rotation_update_audit_events ORDER BY occurred_at DESC LIMIT 1`).Scan(&actor, &target))
	require.Equal(t, "internal_system", actor)
	require.Equal(t, h.UUID("org-b"), target)
	scheduleAuditRows(t, h)
}

func TestScheduleUpdateAuditFailureAtomicity(t *testing.T) {
	h := scheduleAuditHarness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	_, err := h.App().DB().Exec(`CREATE FUNCTION schedule_audit_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome='committed' THEN RAISE EXCEPTION USING MESSAGE='SYNTHETIC_SQL_SECRET',DETAIL='SYNTHETIC_SQL_DETAIL'; END IF; RETURN NEW; END $$; CREATE TRIGGER schedule_audit_reject BEFORE INSERT ON schedule_rotation_update_audit_events FOR EACH ROW EXECUTE FUNCTION schedule_audit_reject()`)
	require.NoError(t, err)
	before := serviceManagementSnapshot(t, h)
	wait := h.ExpectBackendError("schedule.update transaction failed")
	r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateSchedule(input:{id:%q,description:"Must rollback"})}`, h.UUID("schedule-a")))
	wait()
	require.NotEmpty(t, r.Errors)
	require.Equal(t, before, serviceManagementSnapshot(t, h))
	var outcome, reason string
	var effect bool
	require.NoError(t, h.App().DB().QueryRow(`SELECT outcome,reason_code,schedule_row_written FROM schedule_rotation_update_audit_events`).Scan(&outcome, &reason, &effect))
	require.Equal(t, "tx_failed", outcome)
	require.Equal(t, "audit_write_failed", reason)
	require.False(t, effect)
	require.NotContains(t, scheduleAuditRows(t, h), "SYNTHETIC_SQL")
}

func TestScheduleUpdateAuditVisibilityAndLocks(t *testing.T) {
	h := scheduleAuditHarness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tx, err := h.App().DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	var blocker int
	require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&blocker))
	_, err = tx.Exec(`LOCK TABLE schedule_rotation_update_audit_events IN SHARE MODE`)
	require.NoError(t, err)
	done := make(chan *stepOrganizationResponse, 1)
	defer func() {
		_ = tx.Rollback()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("mutation did not finish")
		}
	}()
	go func() {
		done <- stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateSchedule(input:{id:%q,description:"Atomic visibility"})}`, h.UUID("schedule-a")))
	}()
	require.Eventually(t, func() bool {
		var n int
		err := h.App().DB().QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, blocker).Scan(&n)
		return err == nil && n == 1
	}, 10*time.Second, 10*time.Millisecond)
	var old string
	require.NoError(t, h.App().DB().QueryRow(`SELECT description FROM schedules WHERE id=$1`, h.UUID("schedule-a")).Scan(&old))
	require.Empty(t, old)
	require.Zero(t, scheduleAuditCount(t, h))
	probe, err := h.App().DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = probe.Exec(`SELECT id FROM schedules WHERE id=$1 FOR UPDATE NOWAIT`, h.UUID("schedule-a"))
	require.Error(t, err)
	require.NoError(t, probe.Rollback())
	// Independent SQL control; concurrent legacy Mutation capacity is exercised
	// separately on the same wrapped pool by CancellationReleaseBarrier.
	other, err := h.App().DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = other.ExecContext(ctx, `UPDATE schedules SET description='Unrelated control' WHERE id=$1`, h.UUID("schedule-c"))
	require.NoError(t, err)
	require.NoError(t, other.Rollback())
	require.NoError(t, tx.Rollback())
	select {
	case r := <-done:
		require.Empty(t, r.Errors)
		done <- nil
	case <-ctx.Done():
		t.Fatal("update timed out")
	}
	var actual string
	require.NoError(t, h.App().DB().QueryRow(`SELECT description FROM schedules WHERE id=$1`, h.UUID("schedule-a")).Scan(&actual))
	require.Equal(t, "Atomic visibility", actual)
	require.Equal(t, 1, scheduleAuditCount(t, h))
	scheduleAuditRows(t, h)
}
