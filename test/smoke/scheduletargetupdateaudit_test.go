package smoke

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/organization"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/util/timeutil"
)

func u03App(h *harness.Harness) *graphqlapp.App {
	a := sd5App(h)
	a.RuleStore = h.App().ScheduleRuleStore
	return a
}

func u03Harness(t *testing.T) *harness.Harness {
	t.Helper()
	if os.Getenv("MS_ONCALL_CORE_MIGRATION_TEST_POSTGRES_ENABLE") != "1" {
		t.Skip("explicit isolated PostgreSQL opt-in required")
	}
	require.NotEmpty(t, os.Getenv("MS_ONCALL_U03_TEST_CLUSTER_MARKER"))
	h := scheduleAuditHarness(t)
	var dir, marker, system, address string
	var tls bool
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_setting('data_directory'),current_setting('cluster_name'),(SELECT system_identifier::text FROM pg_control_system()),host(inet_server_addr()),(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())`).Scan(&dir, &marker, &system, &address, &tls))
	require.Equal(t, os.Getenv("MS_ONCALL_U03_TEST_DATA_DIRECTORY"), dir)
	require.Equal(t, os.Getenv("MS_ONCALL_U03_TEST_CLUSTER_MARKER"), marker)
	require.Equal(t, os.Getenv("MS_ONCALL_U03_TEST_SYSTEM_ID"), system)
	require.Equal(t, "127.0.0.1", address)
	require.Equal(t, "verify-full", os.Getenv("PGSSLMODE"))
	require.True(t, tls)
	// Independent transactional record of actual deleted rows, including scope.
	_, err := h.App().DB().Exec(`CREATE TABLE u03_actual_deleted AS SELECT id,schedule_id,tgt_user_id,tgt_rotation_id FROM schedule_rules WHERE false;
CREATE FUNCTION u03_capture_deleted() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN INSERT INTO u03_actual_deleted VALUES(OLD.id,OLD.schedule_id,OLD.tgt_user_id,OLD.tgt_rotation_id); RETURN OLD; END$$;
CREATE TRIGGER u03_capture_deleted AFTER DELETE ON schedule_rules FOR EACH ROW EXECUTE FUNCTION u03_capture_deleted()`)
	require.NoError(t, err)
	return h
}

func u03Target(t *testing.T, h *harness.Harness, kind string) assignment.RawTarget {
	t.Helper()
	if kind == "rotation" {
		return assignment.RawTarget{Type: assignment.TargetTypeRotation, ID: sd6Root(t, h, sraudit.Rotation, harness.SmokeOrganizationID)}
	}
	return assignment.RawTarget{Type: assignment.TargetTypeUser, ID: h.UUID("user-a")}
}

func u03Rule(t *testing.T, h *harness.Harness, sched string, target assignment.RawTarget, age int) string {
	t.Helper()
	id := uuid.NewString()
	column := "tgt_user_id"
	if target.Type == assignment.TargetTypeRotation {
		column = "tgt_rotation_id"
	}
	_, err := h.App().DB().Exec(`INSERT INTO schedule_rules(id,schedule_id,`+column+`,created_at) VALUES($1,$2,$3,'2020-01-01'::timestamptz+$4*'1 second'::interval)`, id, sched, target.ID, age)
	require.NoError(t, err)
	return id
}

func u03IDs(t *testing.T, h *harness.Harness, table string) []string {
	t.Helper()
	rows, err := h.App().DB().Query(`SELECT id::text FROM ` + table + ` ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(t, rows.Err())
	return out
}

func u03Count(t *testing.T, h *harness.Harness) int {
	t.Helper()
	var n int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE operation='updateScheduleTarget' AND record_kind='success_witness'`).Scan(&n))
	return n
}

func u03AssertEffects(t *testing.T, h *harness.Harness, root string, target assignment.RawTarget, want []string) {
	t.Helper()
	var raw []byte
	var schema, version int
	var typ, org, outcome, reason, mechanism, cause string
	require.NoError(t, h.App().DB().QueryRow(`SELECT effects,schema_version,effects_version,root_type,target_organization_id,outcome,reason_code,deletion_mechanism,cause FROM schedule_rotation_delete_audit_events WHERE operation='updateScheduleTarget' AND root_id=$1 AND record_kind='success_witness'`, root).Scan(&raw, &schema, &version, &typ, &org, &outcome, &reason, &mechanism, &cause))
	require.Equal(t, 2, schema)
	require.Equal(t, 2, version)
	require.Equal(t, "schedule", typ)
	require.Equal(t, harness.SmokeOrganizationID, org)
	require.Equal(t, "committed", outcome)
	require.Equal(t, "children_deleted", reason)
	require.Equal(t, "explicit_sql", mechanism)
	require.Equal(t, "update_induced", cause)
	var effects []sraudit.Effect
	require.NoError(t, json.Unmarshal(raw, &effects))
	got := []string{}
	for _, f := range effects {
		require.Equal(t, sraudit.Rule, f.ResourceType)
		require.Equal(t, root, f.RootID.String())
		require.Equal(t, org, f.TargetOrganizationID.String())
		require.NotNil(t, f.RuleDeletion)
		require.Equal(t, root, f.RuleDeletion.ScheduleID.String())
		require.Equal(t, target.ID, f.RuleDeletion.TargetID.String())
		kind := "user"
		if target.Type == assignment.TargetTypeRotation {
			kind = "rotation"
		}
		require.Equal(t, kind, f.RuleDeletion.TargetKind)
		require.Equal(t, "EXPLICIT", f.Provenance)
		require.Equal(t, "explicit_sql", f.DeletionMechanism)
		require.Equal(t, "update_induced", f.Cause)
		got = append(got, f.ResourceUUID.String())
	}
	require.ElementsMatch(t, want, got)
	require.ElementsMatch(t, u03IDs(t, h, "u03_actual_deleted"), got, "independent AFTER DELETE rows must exactly equal persistent witness effects")
	t.Logf("actual PostgreSQL deleted UUIDs=%v; persistent audit effects=%v", want, got)
}

func TestScheduleTargetUpdateNativeRuleMatrix(t *testing.T) {
	for _, kind := range []string{"user", "rotation"} {
		for _, tc := range []struct {
			name         string
			old, desired int
			changed      bool
		}{
			{"nil_empty_noop", 0, 0, false}, {"same", 3, 3, false}, {"same_count_time_changed", 3, 3, true},
			{"add_only", 1, 3, false}, {"delete_one_input_ids_ignored", 3, 2, false}, {"delete_multiple", 4, 1, false}, {"clear", 3, 0, false},
			{"created_at_tie_id_order", 3, 2, false}, {"nil_existing_legacy_clear", 3, 0, false},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				h := u03Harness(t)
				root, other := h.UUID("schedule-a"), h.UUID("schedule-c")
				target := u03Target(t, h, kind)
				before := []string{}
				for i := range tc.old {
					before = append(before, u03Rule(t, h, root, target, i))
				}
				if tc.name == "created_at_tie_id_order" {
					_, err := h.App().DB().Exec(`UPDATE schedule_rules SET created_at='2020-01-01' WHERE schedule_id=$1`, root)
					require.NoError(t, err)
					slices.Sort(before)
				}
				otherTarget := u03Target(t, h, "rotation")
				untouched := []string{u03Rule(t, h, root, otherTarget, 0), u03Rule(t, h, other, target, 0)}
				inputs := make([]graphql2.ScheduleRuleInput, tc.desired)
				for i := range inputs {
					fake := uuid.NewString()
					inputs[i].ID = &fake // IDs are deliberately unrelated to the positional tail.
					if tc.changed {
						start := timeutil.Clock(8 * time.Hour)
						inputs[i].Start = &start
					}
				}
				if tc.name == "nil_empty_noop" || tc.name == "nil_existing_legacy_clear" {
					inputs = nil
				}
				ok, err := u03App(h).Mutation().UpdateScheduleTarget(sd3System(), graphql2.ScheduleTargetInput{ScheduleID: &root, Target: &target, Rules: inputs})
				require.NoError(t, err)
				require.True(t, ok)
				after, err := u03App(h).RuleStore.FindByTargetTx(sd3System(), nil, root, target)
				require.NoError(t, err)
				require.Len(t, after, tc.desired)
				for i, r := range after {
					if i < len(before) {
						require.Equal(t, before[i], r.ID, "created_at,id positional update preserves the first N real UUIDs")
					} else {
						require.NotEqual(t, uuid.Nil, uuid.MustParse(r.ID))
						require.NotEqual(t, *inputs[i].ID, r.ID)
					}
					if tc.changed {
						require.Equal(t, timeutil.Clock(8*time.Hour), r.Start)
					}
				}
				for _, id := range untouched {
					require.Contains(t, u03IDs(t, h, "schedule_rules"), id)
				}
				if tc.old > tc.desired {
					require.Equal(t, 1, u03Count(t, h))
					u03AssertEffects(t, h, root, target, before[tc.desired:])
				} else {
					require.Zero(t, u03Count(t, h))
					require.Empty(t, u03IDs(t, h, "u03_actual_deleted"))
				}
				require.Equal(t, 1, serviceManagementCount(t, h, "schedules", root))
			})
		}
	}
}

func TestScheduleTargetUpdateNativeReceiptScopeAndZero(t *testing.T) {
	h := u03Harness(t)
	root, other := h.UUID("schedule-a"), h.UUID("schedule-c")
	target, different := u03Target(t, h, "user"), u03Target(t, h, "rotation")
	id := u03Rule(t, h, root, target, 0)
	keep := []string{u03Rule(t, h, other, target, 0), u03Rule(t, h, root, different, 0)}
	tx, err := h.App().DB().BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	receipts, err := u03App(h).RuleStore.DeleteManyReceiptTx(sd3System(), tx, root, target, append(slices.Clone(keep), uuid.NewString(), id))
	require.NoError(t, err)
	require.Len(t, receipts, 1)
	require.Equal(t, id, receipts[0].ID.String())
	require.Equal(t, root, receipts[0].ScheduleID.String())
	require.Equal(t, "user", receipts[0].TargetKind)
	require.Equal(t, target.ID, receipts[0].TargetID.String())
	receipts, err = u03App(h).RuleStore.DeleteManyReceiptTx(sd3System(), tx, root, target, []string{id})
	require.NoError(t, err)
	require.Empty(t, receipts, "actual zero rows, despite a nonempty selector")
	require.NoError(t, tx.Rollback())
	require.ElementsMatch(t, append(keep, id), u03IDs(t, h, "schedule_rules"))
	require.Empty(t, u03IDs(t, h, "u03_actual_deleted"))
}

func TestScheduleTargetUpdateNativeAuditFailureRollbackAndCreation(t *testing.T) {
	h := u03Harness(t)
	db := h.App().DB()
	root := h.UUID("schedule-a")
	target := u03Target(t, h, "user")
	before := []string{u03Rule(t, h, root, target, 0), u03Rule(t, h, root, target, 1)}
	_, err := db.Exec(`CREATE FUNCTION u03_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_AUDIT_FAILURE'; END$$;
CREATE TRIGGER u03_fail_audit BEFORE INSERT ON schedule_rotation_delete_audit_events FOR EACH ROW WHEN(NEW.schema_version=2 AND NEW.record_kind='success_witness') EXECUTE FUNCTION u03_fail_audit()`)
	require.NoError(t, err)
	start := timeutil.Clock(8 * time.Hour)
	_, err = u03App(h).Mutation().UpdateScheduleTarget(sd3System(), graphql2.ScheduleTargetInput{ScheduleID: &root, Target: &target, Rules: []graphql2.ScheduleRuleInput{{Start: &start}}})
	require.Error(t, err)
	require.ElementsMatch(t, before, u03IDs(t, h, "schedule_rules"))
	require.Empty(t, u03IDs(t, h, "u03_actual_deleted"))
	require.Zero(t, u03Count(t, h))
	var effects, outcome, kind, actualStart string
	require.NoError(t, db.QueryRow(`SELECT effects::text,outcome,record_kind FROM schedule_rotation_delete_audit_events`).Scan(&effects, &outcome, &kind))
	require.Equal(t, "[]", effects)
	require.Equal(t, "tx_failed", outcome)
	require.Equal(t, "attempt_observation", kind)
	require.NoError(t, db.QueryRow(`SELECT start_time::text FROM schedule_rules WHERE id=$1`, before[0]).Scan(&actualStart))
	require.Equal(t, "00:00:00", actualStart, "earlier positional UPDATE also rolls back")
	// Actual CreateSchedule, not merely a helper invocation. Persisted audit rows
	// must not misrepresent initial rules as an Update deletion.
	org := harness.SmokeOrganizationID
	ikSetAuthority(t, h, "ORG_ADMIN", true)
	created, err := u03App(h).Mutation().CreateSchedule(servicePlatformAdminContext(t, h), graphql2.CreateScheduleInput{Name: "U03 nested initial rules", TimeZone: "UTC", TargetOrganizationID: &org, Targets: []graphql2.ScheduleTargetInput{{Target: &target, Rules: []graphql2.ScheduleRuleInput{{}, {}}}}})
	require.NoError(t, err)
	var rules, audits int
	require.NoError(t, db.QueryRow(`SELECT (SELECT count(*) FROM schedule_rules WHERE schedule_id=$1),(SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND operation='updateScheduleTarget')`, created.ID).Scan(&rules, &audits))
	require.Equal(t, 2, rules)
	require.Zero(t, audits)
}

func TestScheduleTargetUpdateNativeHTTPRoles(t *testing.T) {
	for _, mode := range []string{"org_admin", "member", "foreign_org_admin", "foreign_pa", "default_pa"} {
		t.Run(mode, func(t *testing.T) {
			h := u03Harness(t)
			pa := mode == "foreign_pa" || mode == "default_pa"
			role := "ORG_ADMIN"
			if mode == "member" {
				role = "ORG_MEMBER"
			}
			ikSetAuthority(t, h, role, pa)
			home, org := harness.SmokeOrganizationID, harness.SmokeOrganizationID
			if mode == "default_pa" {
				home = organization.DefaultOrganizationID
				_, err := h.App().DB().Exec(`UPDATE user_organization_assignments SET effective_organization_id=$2,effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, h.UUID("user-a"), home)
				require.NoError(t, err)
			}
			if mode == "foreign_pa" || mode == "foreign_org_admin" || mode == "default_pa" {
				org = h.UUID("org-b")
			}
			root := sd6Root(t, h, sraudit.Schedule, org)
			target := u03Target(t, h, "user")
			id := u03Rule(t, h, root, target, 0)
			r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation U03{...F} fragment F on Mutation{alias:updateScheduleTarget(input:{scheduleID:%q,target:{type:user,id:%q},rules:[]})}`, root, target.ID))
			allowed := mode != "member" && mode != "foreign_org_admin"
			if allowed {
				require.Empty(t, r.Errors)
				require.Equal(t, 1, u03Count(t, h))
				require.NotContains(t, u03IDs(t, h, "schedule_rules"), id)
			} else {
				require.NotEmpty(t, r.Errors)
				require.Zero(t, u03Count(t, h))
				require.Contains(t, u03IDs(t, h, "schedule_rules"), id)
			}
			var actor, actualHome, request, execution, attempt string
			var targetOrg sql.NullString
			require.NoError(t, h.App().DB().QueryRow(`SELECT actor_id,home_organization_id,target_organization_id,request_id,execution_id,attempt_id FROM schedule_rotation_delete_audit_events WHERE operation='updateScheduleTarget'`).Scan(&actor, &actualHome, &targetOrg, &request, &execution, &attempt))
			require.Equal(t, h.UUID("user-a"), actor)
			require.Equal(t, home, actualHome)
			for _, id := range []string{request, execution, attempt} {
				require.NotEqual(t, uuid.Nil, uuid.MustParse(id))
			}
			if allowed {
				require.Equal(t, org, targetOrg.String)
			} else {
				require.False(t, targetOrg.Valid)
			}
		})
	}
}
