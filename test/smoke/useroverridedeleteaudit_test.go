package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/override"
	uoaudit "github.com/target/goalert/override/deleteaudit"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func sd7App(h *harness.Harness) *graphqlapp.App {
	a := sd5App(h)
	a.OverrideStore = h.App().OverrideStore
	return a
}
func sd7User(t *testing.T, h *harness.Harness) string {
	t.Helper()
	u := uuid.NewString()
	_, err := h.App().DB().Exec(`INSERT INTO users(id,name,email) VALUES($1,'SYNTHETIC_PRIVATE','SYNTHETIC_PRIVATE@example.invalid')`, u)
	require.NoError(t, err)
	return u
}
func sd7Override(t *testing.T, h *harness.Harness, s string, add, remove any, start, end time.Time) string {
	t.Helper()
	id := uuid.NewString()
	_, err := h.App().DB().Exec(`INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,remove_user_id,start_time,end_time) VALUES($1,$2,$3,$4,$5,$6)`, id, s, add, remove, start, end)
	require.NoError(t, err)
	return id
}
func sd7Root(t *testing.T, h *harness.Harness, s string) string {
	return sd7Override(t, h, s, sd7User(t, h), nil, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC))
}
func sd7Count(t *testing.T, h *harness.Harness) int {
	t.Helper()
	var n int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM user_override_delete_audit_events WHERE record_kind='success_witness'`).Scan(&n))
	return n
}
func sd7Rows(t *testing.T, h *harness.Harness) string {
	t.Helper()
	var s string
	require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(e)),'[]')::text FROM user_override_delete_audit_events e`).Scan(&s))
	return s
}
func sd7Before(t *testing.T, h *harness.Harness, id string) uoaudit.Before {
	t.Helper()
	var b uoaudit.Before
	var raw []byte
	require.NoError(t, h.App().DB().QueryRow(`SELECT jsonb_build_object('version',1,'root_id',o.id,'parent_schedule_id',o.tgt_schedule_id,'target_organization_id',s.organization_id,'add_user_id',o.add_user_id,'remove_user_id',o.remove_user_id,'start',o.start_time,'end',o.end_time,'row_version',o.xmin::text::bigint) FROM user_overrides o JOIN schedules s ON s.id=o.tgt_schedule_id WHERE o.id=$1`, id).Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &b))
	b.Start, b.End = b.Start.UTC(), b.End.UTC()
	return b
}
func TestUODeleteAuditSignedHTTPBefore(t *testing.T) {
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
	u, v := sd7User(t, h), sd7User(t, h)
	// CURRENT BEHAVIOR — CONFIRMED: unrelated OrgMember may delete these Overrides.
	// OWNER TARGET POLICY — DEFERRED: this does not accept or repair that RBAC gap.
	expected := map[string]uoaudit.Before{}
	ids := []string{}
	for _, phase := range []string{"past", "active", "future"} {
		for _, kind := range []string{"add", "remove", "replace"} {
			start := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
			end := start.Add(2 * time.Hour)
			if phase == "past" {
				start = start.Add(-24 * time.Hour)
				end = end.Add(-24 * time.Hour)
			}
			if phase == "future" {
				start = start.Add(24 * time.Hour)
				end = end.Add(24 * time.Hour)
			}
			u, v := sd7User(t, h), sd7User(t, h)
			var add, remove any
			if kind != "remove" {
				add = u
			}
			if kind != "add" {
				remove = v
			}
			id := sd7Override(t, h, s, add, remove, start, end)
			ids = append(ids, id)
			expected[id] = sd7Before(t, h, id)
		}
	}
	response := sd1HTTP(t, h, sd6Query("userOverride", append(ids, ids[0])), "")
	require.Empty(t, response.Errors)
	require.Equal(t, 9, sd7Count(t, h))
	var rows []struct {
		RootID                      string         `json:"root_id"`
		Parent                      string         `json:"parent_schedule_id"`
		Org                         string         `json:"target_organization_id"`
		Actor                       string         `json:"actor_id"`
		Role                        string         `json:"authority_role"`
		Provenance                  string         `json:"provenance"`
		Effects                     []any          `json:"effects"`
		Before                      uoaudit.Before `json:"before_context"`
		Request, Execution, Attempt string
	}
	require.NoError(t, json.Unmarshal([]byte(sd7Rows(t, h)), &rows))
	for _, e := range rows {
		require.Equal(t, expected[e.RootID], e.Before)
		for _, user := range []*uuid.UUID{e.Before.AddUserID, e.Before.RemoveUserID} {
			if user != nil {
				require.Equal(t, 1, serviceManagementCount(t, h, "users", user.String()))
			}
		}
		require.Equal(t, s, e.Parent)
		require.Equal(t, harness.SmokeOrganizationID, e.Org)
		require.Equal(t, h.UUID("user-a"), e.Actor)
		require.Equal(t, "org_member", e.Role)
		require.Equal(t, "EXPLICIT", e.Provenance)
		require.Empty(t, e.Effects)
		require.Zero(t, serviceManagementCount(t, h, "user_overrides", e.RootID))
	}
	for table, id := range map[string]string{"schedules": s, "users": u} {
		require.Equal(t, 1, serviceManagementCount(t, h, table, id))
	}
	require.Equal(t, 1, serviceManagementCount(t, h, "users", v))
	require.NotContains(t, sd7Rows(t, h), "SYNTHETIC_")
	var correlations int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(DISTINCT ROW(request_id,execution_id,attempt_id)) FROM user_override_delete_audit_events`).Scan(&correlations))
	require.Equal(t, 1, correlations)
}
func TestUODeleteAuditHTTPRolesAndCompleteSet(t *testing.T) {
	for _, mode := range []string{"member", "org_admin", "home_pa", "foreign_member", "foreign_admin", "foreign_pa", "default_pa", "missing", "partial_foreign"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			h := sd1Harness(t)
			pa := strings.Contains(mode, "pa")
			role := "ORG_MEMBER"
			if strings.Contains(mode, "admin") {
				role = "ORG_ADMIN"
			}
			ikSetAuthority(t, h, role, pa)
			db := h.App().DB()
			if mode == "default_pa" {
				_, err := db.Exec(`UPDATE user_organization_assignments SET effective_organization_id=$2,effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, h.UUID("user-a"), organization.DefaultOrganizationID)
				require.NoError(t, err)
			}
			org := harness.SmokeOrganizationID
			if strings.HasPrefix(mode, "foreign") {
				org = h.UUID("org-b")
			}
			s := sd6Root(t, h, "schedule", org)
			id := sd7Root(t, h, s)
			ids := []string{id, id}
			if mode == "missing" {
				ids = append(ids, uuid.NewString())
			}
			if mode == "partial_foreign" {
				ids = append(ids, sd7Root(t, h, sd6Root(t, h, "schedule", h.UUID("org-b"))))
			}
			allowed := mode == "member" || mode == "org_admin" || mode == "home_pa"
			var expected func()
			if !allowed && mode != "default_pa" {
				expected = h.ExpectBackendError("sql: no rows in result set")
			}
			r := sd1HTTP(t, h, sd6Query("userOverride", ids), "")
			if expected != nil {
				expected()
			}
			if allowed {
				require.Empty(t, r.Errors)
				require.Equal(t, 1, sd7Count(t, h))
			} else {
				require.NotEmpty(t, r.Errors)
				require.Zero(t, sd7Count(t, h))
				require.Equal(t, 1, serviceManagementCount(t, h, "user_overrides", id))
			}
		})
	}
}
func TestUODeleteAuditLimitsSystemAndIdentity(t *testing.T) {
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
	id := sd7Root(t, h, s)
	ids := make([]string, 51)
	for i := range ids {
		ids[i] = id
	}
	r := stepOrganizationQuery(t, h, sd6Query("userOverride", ids))
	require.NotEmpty(t, r.Errors)
	require.Zero(t, sd7Count(t, h))
	r = stepOrganizationQuery(t, h, sd6Query("userOverride", ids[:50]))
	require.Empty(t, r.Errors)
	require.Equal(t, 1, sd7Count(t, h))
	ids = nil
	for range 50 {
		ids = append(ids, sd7Root(t, h, s))
	}
	r = stepOrganizationQuery(t, h, sd6Query("userOverride", ids))
	require.Empty(t, r.Errors)
	require.Equal(t, 51, sd7Count(t, h))
	r = stepOrganizationQuery(t, h, sd6Query("userOverride", []string{"malformed"}))
	require.NotEmpty(t, r.Errors)
	app := sd7App(h)
	for range 2 {
		ok, err := app.Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeUserOverride, uuid.NewString())})
		require.NoError(t, err)
		require.True(t, ok)
	}
	require.Equal(t, 51, sd7Count(t, h))
	for _, ctx := range []context.Context{context.Background(), permission.SystemContext(permission.UserContext(context.Background(), uuid.NewString(), permission.RoleAdmin), "SYNTHETIC"), permission.SourceContext(sd3System(), &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()})} {
		id := sd7Root(t, h, s)
		_, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeUserOverride, id)})
		require.Error(t, err)
		require.Equal(t, 1, serviceManagementCount(t, h, "user_overrides", id))
	}
	var falseRoot int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM user_override_delete_audit_events WHERE actor_kind='unknown' AND record_kind='success_witness'`).Scan(&falseRoot))
	require.Zero(t, falseRoot)
}
func TestUODeleteAuditRollback(t *testing.T) {
	for _, mode := range []string{"receipt_suppressed", "receipt_changed", "append", "late_service", "deferred_commit"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			h := sd1Harness(t)
			ikSetAuthority(t, h, "ORG_ADMIN", true)
			db := h.App().DB()
			s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
			id := sd7Root(t, h, s)
			before := sd7Before(t, h, id)
			var q string
			switch mode {
			case "receipt_suppressed":
				q = `CREATE FUNCTION sd7_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NULL;END;$$;CREATE TRIGGER sd7_fault BEFORE DELETE ON user_overrides FOR EACH ROW EXECUTE FUNCTION sd7_fault()`
			case "receipt_changed":
				q = `CREATE FUNCTION sd7_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN UPDATE schedules SET organization_id='` + h.UUID("org-b") + `' WHERE id=OLD.tgt_schedule_id; RETURN OLD;END;$$;CREATE TRIGGER sd7_fault BEFORE DELETE ON user_overrides FOR EACH ROW EXECUTE FUNCTION sd7_fault()`
			case "append":
				q = `CREATE FUNCTION sd7_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE';END;$$;CREATE TRIGGER sd7_fault BEFORE INSERT ON user_override_delete_audit_events FOR EACH ROW WHEN (NEW.record_kind='success_witness') EXECUTE FUNCTION sd7_fault()`
			case "late_service":
				q = `CREATE FUNCTION sd7_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE';END;$$;CREATE TRIGGER sd7_fault BEFORE DELETE ON services FOR EACH ROW EXECUTE FUNCTION sd7_fault()`
			case "deferred_commit":
				q = `CREATE FUNCTION sd7_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='SYNTHETIC_PRIVATE';END;$$;CREATE CONSTRAINT TRIGGER sd7_fault AFTER DELETE ON user_overrides DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sd7_fault()`
			}
			_, err := db.Exec(q)
			require.NoError(t, err)
			others := []string{}
			if mode == "late_service" {
				others = append(others, fmt.Sprintf(`{type:service,id:%q}`, h.UUID("service-a")))
			}
			expected := h.ExpectBackendError("deleteAll transaction failed")
			r := stepOrganizationQuery(t, h, sd6Query("userOverride", []string{id}, others...))
			expected()
			require.NotEmpty(t, r.Errors)
			require.Zero(t, sd7Count(t, h))
			require.Equal(t, before, sd7Before(t, h, id))
			require.Equal(t, 1, serviceManagementCount(t, h, "services", h.UUID("service-a")))
		})
	}
}
func TestUODeleteAuditMixedUser(t *testing.T) {
	for _, pa := range []bool{false, true} {
		t.Run(fmt.Sprintf("platform_admin=%t", pa), func(t *testing.T) {
			t.Parallel()
			h := sd1Harness(t)
			ikSetAuthority(t, h, "ORG_MEMBER", pa)
			s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
			u := sd7User(t, h)
			id := sd7Override(t, h, s, u, nil, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC))
			r := sd1HTTP(t, h, sd6Query("userOverride", []string{id}, fmt.Sprintf(`{type:user,id:%q}`, u)), "")
			if pa {
				require.Empty(t, r.Errors)
				require.Equal(t, 1, sd7Count(t, h))
				require.Zero(t, serviceManagementCount(t, h, "users", u))
			} else {
				require.NotEmpty(t, r.Errors)
				require.Zero(t, sd7Count(t, h))
				require.Equal(t, 1, serviceManagementCount(t, h, "user_overrides", id))
				require.Equal(t, 1, serviceManagementCount(t, h, "users", u))
			}
			require.Equal(t, 1, serviceManagementCount(t, h, "schedules", s))
			var roots int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM user_override_delete_audit_events WHERE root_type='user'`).Scan(&roots))
			require.Zero(t, roots)
		})
	}
}
func TestUODeleteAuditControlledCommit(t *testing.T) {
	for _, mode := range []string{"commit_then_error", "rollback_then_error", "completion_unknown", "begin_failed"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			h := sd1Harness(t)
			s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
			id := sd7Root(t, h, s)
			var database string
			require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&database))
			cfg, err := pgx.ParseConfig(harness.DBURL(database))
			require.NoError(t, err)
			connector := &serviceAuditFaultConnector{base: stdlib.GetConnector(*cfg), mode: mode}
			controlled := sql.OpenDB(connector)
			defer controlled.Close()
			controlled.SetMaxOpenConns(1)
			app := sd7App(h)
			app.DB = controlled
			app.OverrideStore, err = override.NewStore(t.Context(), controlled)
			require.NoError(t, err)
			ok, err := app.Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeUserOverride, id)})
			require.Error(t, err)
			require.False(t, ok)
			require.EqualValues(t, 2, connector.begins.Load())
			want := 0
			if mode == "commit_then_error" || mode == "completion_unknown" {
				want = 1
			}
			require.Equal(t, want, sd7Count(t, h))
			require.Equal(t, 1-want, serviceManagementCount(t, h, "user_overrides", id))
		})
	}
}
