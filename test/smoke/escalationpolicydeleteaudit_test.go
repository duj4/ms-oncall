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
	epaudit "github.com/target/goalert/escalation/deleteaudit"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/test/smoke/harness"
)

func sd5EP(t *testing.T, h *harness.Harness, org string) string {
	t.Helper()
	id := uuid.NewString()
	_, err := h.App().DB().Exec(`INSERT INTO escalation_policies(id,organization_id,name) VALUES($1::uuid,$2,$3)`, id, org, "SD5 "+id)
	require.NoError(t, err)
	return id
}
func sd5Query(ids []string, others ...string) string {
	targets := append([]string{}, others...)
	for _, id := range ids {
		targets = append(targets, fmt.Sprintf(`{type:escalationPolicy,id:%q}`, id))
	}
	return `mutation{deleteAll(input:[` + strings.Join(targets, ",") + `])}`
}
func sd5Rows(t *testing.T, h *harness.Harness) string {
	t.Helper()
	var s string
	require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY event_id),'[]')::text FROM escalation_policy_delete_audit_events e`).Scan(&s))
	return s
}
func sd5Count(t *testing.T, h *harness.Harness) int {
	t.Helper()
	var n int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM escalation_policy_delete_audit_events WHERE record_kind='success_witness'`).Scan(&n))
	return n
}
func sd5App(h *harness.Harness) *graphqlapp.App {
	return &graphqlapp.App{DB: h.App().DB(), PolicyStore: h.App().EscalationStore, ServiceStore: h.App().ServiceStore, IntKeyStore: h.App().IntegrationKeyStore, ScheduleStore: h.App().ScheduleStore, RotationStore: h.App().RotationStore, UserStore: h.App().UserStore, CMStore: h.App().ContactMethodStore, NRStore: h.App().NotificationRuleStore, AuthHandler: h.App().AuthHandler}
}
func sd5Effects(t *testing.T, h *harness.Harness, root string) []epaudit.Effect {
	t.Helper()
	var raw string
	require.NoError(t, h.App().DB().QueryRow(`SELECT effects::text FROM escalation_policy_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, root).Scan(&raw))
	var effects []epaudit.Effect
	require.NoError(t, json.Unmarshal([]byte(raw), &effects))
	return effects
}
func sd5Step(t *testing.T, h *harness.Harness, root string) string {
	t.Helper()
	id := uuid.NewString()
	_, err := h.App().DB().Exec(`INSERT INTO escalation_policy_steps(id,escalation_policy_id) VALUES($1,$2)`, id, root)
	require.NoError(t, err)
	return id
}

func TestEscalationPolicyDeleteAuditHTTPRoles(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"org_admin", "foreign_pa", "default_pa", "same_org_batch", "member", "foreign_org_admin", "cross_org_pa", "missing", "valid_foreign_org_admin", "pa_missing"} {
		t.Run(mode, func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			pa := strings.Contains(mode, "pa")
			ikSetAuthority(t, h, "ORG_ADMIN", pa)
			if mode == "member" {
				ikSetAuthority(t, h, "ORG_MEMBER", false)
			}
			home, target := harness.SmokeOrganizationID, harness.SmokeOrganizationID
			if mode == "foreign_pa" || mode == "default_pa" || mode == "foreign_org_admin" {
				target = h.UUID("org-b")
			}
			if mode == "default_pa" {
				home = organization.DefaultOrganizationID
				_, err := db.Exec(`UPDATE user_organization_assignments SET effective_organization_id=$2,effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, h.UUID("user-a"), home)
				require.NoError(t, err)
			}
			root := sd5EP(t, h, target)
			ids := []string{root}
			if mode == "same_org_batch" {
				ids = append(ids, sd5EP(t, h, target))
			}
			if mode == "cross_org_pa" {
				ids = append(ids, sd5EP(t, h, h.UUID("org-b")))
			}
			if mode == "missing" || mode == "pa_missing" {
				ids = append(ids, uuid.NewString())
			}
			if mode == "valid_foreign_org_admin" {
				ids = append(ids, sd5EP(t, h, h.UUID("org-b")))
			}
			var expected func()
			if mode == "foreign_org_admin" || mode == "cross_org_pa" || mode == "missing" || mode == "pa_missing" || mode == "valid_foreign_org_admin" {
				expected = h.ExpectBackendError("sql: no rows in result set")
			}
			response := stepOrganizationQuery(t, h, sd5Query(append(ids, root)))
			if expected != nil {
				expected()
			}
			allowed := mode == "org_admin" || mode == "foreign_pa" || mode == "default_pa" || mode == "same_org_batch"
			if !allowed {
				require.NotEmpty(t, response.Errors)
				require.Zero(t, sd5Count(t, h))
				require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policies", root))
				return
			}
			require.Empty(t, response.Errors)
			require.Equal(t, len(ids), sd5Count(t, h))
			var events []map[string]any
			require.NoError(t, json.Unmarshal([]byte(sd5Rows(t, h)), &events))
			var request, execution, attempt any
			for _, e := range events {
				require.Equal(t, h.UUID("user-a"), e["actor_id"])
				require.Equal(t, home, e["home_organization_id"])
				require.Equal(t, target, e["target_organization_id"])
				require.Equal(t, "EXPLICIT", e["provenance"])
				require.Equal(t, "explicit_sql", e["deletion_mechanism"])
				require.Equal(t, "explicit_target", e["cause"])
				require.Empty(t, e["effects"])
				require.Equal(t, 0, serviceManagementCount(t, h, "escalation_policies", e["root_id"].(string)))
				if request == nil {
					request, execution, attempt = e["request_id"], e["execution_id"], e["attempt_id"]
				}
				require.Equal(t, request, e["request_id"])
				require.Equal(t, execution, e["execution_id"])
				require.Equal(t, attempt, e["attempt_id"])
			}
			expected = h.ExpectBackendError("sql: no rows in result set")
			response = stepOrganizationQuery(t, h, sd5Query(ids))
			expected()
			require.NotEmpty(t, response.Errors)
			require.Equal(t, len(ids), sd5Count(t, h))
		})
	}
}

func TestEscalationPolicyDeleteAuditRawLimitsAndSystem(t *testing.T) {
	t.Parallel()
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	root := sd5EP(t, h, harness.SmokeOrganizationID)
	for _, n := range []int{51, 50} {
		ids := make([]string, n)
		for i := range ids {
			ids[i] = root
		}
		r := stepOrganizationQuery(t, h, sd5Query(ids))
		if n == 51 {
			require.NotEmpty(t, r.Errors)
			require.Zero(t, sd5Count(t, h))
			require.NotContains(t, sd5Rows(t, h), root)
		} else {
			require.Empty(t, r.Errors)
			require.Equal(t, 1, sd5Count(t, h))
		}
	}
	ids := []string{}
	for i := 0; i < 50; i++ {
		ids = append(ids, sd5EP(t, h, harness.SmokeOrganizationID))
	}
	r := stepOrganizationQuery(t, h, sd5Query(ids))
	require.Empty(t, r.Errors)
	require.Equal(t, 51, sd5Count(t, h))
	r = stepOrganizationQuery(t, h, sd5Query([]string{"malformed"}))
	require.NotEmpty(t, r.Errors)
	require.Equal(t, 51, sd5Count(t, h))
	app := sd5App(h)
	missing := uuid.NewString()
	for i := 0; i < 2; i++ {
		ok, err := app.Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, missing)})
		require.NoError(t, err)
		require.True(t, ok)
	}
	require.Equal(t, 51, sd5Count(t, h))
	// No authenticated/canonical authority: no resource lookup attribution.
	_, err := app.Mutation().DeleteAll(context.Background(), []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, uuid.NewString())})
	require.Error(t, err)
	var unknownRoots int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM escalation_policy_delete_audit_events WHERE actor_kind='unknown' AND root_id IS NOT NULL`).Scan(&unknownRoots))
	require.Zero(t, unknownRoots)
}

func TestEscalationPolicyDeleteAuditEffectsAndEarlierGroups(t *testing.T) {
	t.Parallel()
	h := sd1Harness(t)
	db := h.App().DB()
	root, unrelated := sd5EP(t, h, harness.SmokeOrganizationID), sd5EP(t, h, harness.SmokeOrganizationID)
	step, otherStep := sd5Step(t, h, root), sd5Step(t, h, unrelated)
	_ = sd5Step(t, h, root)
	// Destination is intentionally sensitive synthetic data, not an audit field.
	channel := uuid.NewString()
	_, err := db.Exec(`INSERT INTO notification_channels(id,name,type,value) VALUES($1,'SD5 channel','WEBHOOK','https://synthetic.invalid/SYNTHETIC_DEST')`, channel)
	require.NoError(t, err)
	user := uuid.NewString()
	_, err = db.Exec(`INSERT INTO users(id,name) VALUES($1,'SD5 synthetic user')`, user)
	require.NoError(t, err)
	for column, id := range map[string]string{"user_id": user, "schedule_id": h.UUID("schedule-a"), "rotation_id": h.UUID("oncall-rotation"), "channel_id": channel} {
		_, err = db.Exec(`INSERT INTO escalation_policy_actions(escalation_policy_step_id,`+column+`) VALUES($1,$2)`, step, id)
		require.NoError(t, err)
	}
	_, err = db.Exec(`INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)`, otherStep, h.UUID("user-a"))
	require.NoError(t, err)
	for _, owner := range []string{h.UUID("user-a"), user} {
		_, err = db.Exec(`INSERT INTO user_favorites(user_id,tgt_escalation_policy_id) VALUES($1,$2)`, owner, root)
		require.NoError(t, err)
	}
	_, err = db.Exec(`INSERT INTO user_favorites(user_id,tgt_escalation_policy_id) VALUES($1,$2)`, h.UUID("user-a"), unrelated)
	require.NoError(t, err)
	// The earlier three groups remove their actions, and User removes its own
	// favorite. Only channel Action and actor's Favorite remain at EP capture.
	ok, err := sd5App(h).Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, root), sd3Target(assignment.TargetTypeSchedule, h.UUID("schedule-a")), sd3Target(assignment.TargetTypeRotation, h.UUID("oncall-rotation")), sd3Target(assignment.TargetTypeUser, user)})
	require.NoError(t, err)
	require.True(t, ok)
	effects := sd5Effects(t, h, root)
	require.Len(t, effects, 4)
	steps, actions, favs := 0, 0, 0
	for _, f := range effects {
		require.Equal(t, root, f.RootID.String())
		require.Equal(t, "CASCADE", f.Provenance)
		switch f.ResourceType {
		case epaudit.Step:
			steps++
		case epaudit.Action:
			actions++
			require.Equal(t, "notification_channel", f.TargetKind)
			require.Equal(t, channel, f.TargetID.String())
			require.Equal(t, step, f.ParentStepID.String())
		case epaudit.Favorite:
			favs++
			require.Equal(t, "relationship_removed", f.Change)
			require.Equal(t, h.UUID("user-a"), f.OwnerUserID.String())
			require.Equal(t, harness.SmokeOrganizationID, f.OwnerOrganizationID.String())
		}
	}
	require.Equal(t, 2, steps)
	require.Equal(t, 1, actions)
	require.Equal(t, 1, favs)
	require.NotContains(t, sd5Rows(t, h), "SYNTHETIC_DEST")
	require.Equal(t, 1, serviceManagementCount(t, h, "notification_channels", channel))
	require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policies", unrelated))
	require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policy_steps", otherStep))
}

func TestEscalationPolicyDeleteAuditProjectionAndUpdateBoundary(t *testing.T) {
	t.Parallel()
	h := sd1Harness(t)
	db := h.App().DB()
	ikSetAuthority(t, h, "ORG_ADMIN", true)
	root := sd5EP(t, h, h.UUID("org-b"))
	step := sd5Step(t, h, root)
	_ = sd5Step(t, h, root)
	channel := uuid.NewString()
	_, err := db.Exec(`INSERT INTO notification_channels(id,name,type,value) VALUES($1,'SD5 safe reference','WEBHOOK','https://synthetic.invalid/SYNTHETIC_DEST')`, channel)
	require.NoError(t, err)
	expectedActions := map[string]string{}
	for column, id := range map[string]string{"user_id": h.UUID("user-a"), "schedule_id": h.UUID("schedule-a"), "rotation_id": h.UUID("oncall-rotation"), "channel_id": channel} {
		action := uuid.NewString()
		_, err = db.Exec(`INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,`+column+`) VALUES($1,$2,$3)`, action, step, id)
		require.NoError(t, err)
		expectedActions[action] = id
	}
	defaultOwner, unknownOwner := uuid.NewString(), uuid.NewString()
	_, err = db.Exec(`INSERT INTO users(id,name,role) VALUES($1,'SD5 default favorite','user'),($2,'SD5 unknown favorite','user')`, defaultOwner, unknownOwner)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,matched_count,authoritative_evaluated_at,source_config_version) VALUES($1,$2,'DEFAULT',NULL,'NONE','ZERO',0,now(),'sd5-owner')`, defaultOwner, organization.DefaultOrganizationID)
	require.NoError(t, err)
	expectedFavorites := map[int64]string{}
	for _, owner := range []string{h.UUID("user-a"), defaultOwner, unknownOwner} {
		var id int64
		require.NoError(t, db.QueryRow(`INSERT INTO user_favorites(user_id,tgt_escalation_policy_id) VALUES($1,$2) RETURNING id`, owner, root).Scan(&id))
		expectedFavorites[id] = owner
	}
	ok, err := sd5App(h).Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, root)})
	require.NoError(t, err)
	require.True(t, ok)
	effects := sd5Effects(t, h, root)
	require.Len(t, effects, 9)
	for _, f := range effects {
		require.Equal(t, h.UUID("org-b"), f.TargetOrganizationID.String())
		switch f.ResourceType {
		case epaudit.Action:
			require.Equal(t, expectedActions[f.ResourceUUID.String()], f.TargetID.String())
			delete(expectedActions, f.ResourceUUID.String())
			require.Equal(t, step, f.ParentStepID.String())
		case epaudit.Favorite:
			require.Equal(t, expectedFavorites[*f.ResourceNumericID], f.OwnerUserID.String())
			delete(expectedFavorites, *f.ResourceNumericID)
			switch f.OwnerUserID.String() {
			case h.UUID("user-a"):
				require.Equal(t, "known_normal", f.OwnerOrgResolution)
				require.Equal(t, harness.SmokeOrganizationID, f.OwnerOrganizationID.String())
			case defaultOwner:
				require.Equal(t, "known_default", f.OwnerOrgResolution)
				require.Equal(t, organization.DefaultOrganizationID, f.OwnerOrganizationID.String())
			case unknownOwner:
				require.Equal(t, "unknown", f.OwnerOrgResolution)
				require.Nil(t, f.OwnerOrganizationID)
			}
		}
	}
	require.Empty(t, expectedActions)
	require.Empty(t, expectedFavorites)
	require.NotContains(t, sd5Rows(t, h), "SYNTHETIC_")
	for table, id := range map[string]string{"users": h.UUID("user-a"), "schedules": h.UUID("schedule-a"), "rotations": h.UUID("oncall-rotation"), "notification_channels": channel} {
		require.Equal(t, 1, serviceManagementCount(t, h, table, id))
	}
	// Existing Update-induced child deletion remains independent of EP root delete.
	root = sd5EP(t, h, harness.SmokeOrganizationID)
	first, removed := sd5Step(t, h, root), sd5Step(t, h, root)
	_, err = db.Exec(`INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)`, first, h.UUID("user-a"))
	require.NoError(t, err)
	r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateEscalationPolicy(input:{id:%q,name:"SD5 updated",stepIDs:[%q]})}`, root, first))
	require.Empty(t, r.Errors)
	require.Zero(t, serviceManagementCount(t, h, "escalation_policy_steps", removed))
	r = stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:1,actions:[]})}`, first))
	require.Empty(t, r.Errors)
	require.Equal(t, 1, sd5Count(t, h))
	var actions int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM escalation_policy_actions WHERE escalation_policy_step_id=$1`, first).Scan(&actions))
	require.Zero(t, actions)
	ok, err = sd5App(h).Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeSchedule, h.UUID("schedule-a"))})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 1, sd5Count(t, h))
	require.Zero(t, sd4Count(t, h))
	require.Zero(t, sd1Count(t, h, "committed"))
}

func TestEscalationPolicyDeleteAuditMixedAtomicity(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"all_success", "without_service", "ep_key", "ep_cmnr", "earlier_group_failure", "remaining_reference", "in_use", "later_group_failure", "ep_append_failure", "key_append_failure", "cmnr_append_failure"} {
		t.Run(mode, func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			ikSetAuthority(t, h, "ORG_ADMIN", true)
			root := h.UUID("policy-b")
			if mode == "without_service" || mode == "ep_key" || mode == "ep_cmnr" {
				root = sd5EP(t, h, h.UUID("org-b"))
			}
			if mode == "remaining_reference" {
				_, err := db.Exec(`INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,'SD5 remaining reference')`, uuid.NewString(), h.UUID("org-b"), root)
				require.NoError(t, err)
			}
			step := sd5Step(t, h, root)
			keyParent := h.UUID("service-b")
			if mode == "key_append_failure" {
				keyParent = h.UUID("service-c")
			}
			key, _ := sd3Key(t, h, keyParent)
			cm, nr := uuid.NewString(), uuid.NewString()
			_, err := db.Exec(`INSERT INTO user_contact_methods(id,user_id,name,dest) VALUES($1,$2,'SD5 CM','{"Type":"builtin-smtp-email","Args":{"email_address":"SYNTHETIC_CM@example.invalid"}}')`, cm, h.UUID("user-a"))
			require.NoError(t, err)
			_, err = db.Exec(`INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,0)`, nr, h.UUID("user-a"), cm)
			require.NoError(t, err)
			others := []string{}
			if mode != "ep_cmnr" {
				others = append(others, fmt.Sprintf(`{type:integrationKey,id:%q}`, key))
			}
			if mode != "ep_key" {
				others = append(others, fmt.Sprintf(`{type:contactMethod,id:%q},{type:notificationRule,id:%q}`, cm, nr))
			}
			if mode == "earlier_group_failure" {
				others = append(others, fmt.Sprintf(`{type:rotation,id:%q}`, h.UUID("oncall-rotation")))
				_, err = db.Exec(`CREATE FUNCTION sd5_earlier_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SYNTHETIC_SQL_DETAIL'; END $$; CREATE TRIGGER sd5_earlier_fail BEFORE DELETE ON rotations FOR EACH ROW EXECUTE FUNCTION sd5_earlier_fail()`)
				require.NoError(t, err)
			}
			if mode != "in_use" && mode != "without_service" && mode != "ep_key" && mode != "ep_cmnr" {
				others = append(others, fmt.Sprintf(`{type:service,id:%q}`, h.UUID("service-b")))
			}
			if mode == "later_group_failure" {
				foreignOwner, foreignCM := uuid.NewString(), uuid.NewString()
				_, err = db.Exec(`INSERT INTO users(id,name) VALUES($1,'SD5 foreign CM owner')`, foreignOwner)
				require.NoError(t, err)
				_, err = db.Exec(`INSERT INTO user_contact_methods(id,user_id,name,dest) VALUES($1,$2,'foreign CM','{"Type":"builtin-smtp-email","Args":{"email_address":"foreign@example.invalid"}}')`, foreignCM, foreignOwner)
				require.NoError(t, err)
				others = append(others, fmt.Sprintf(`{type:contactMethod,id:%q}`, foreignCM))
			}
			if strings.HasSuffix(mode, "append_failure") {
				table := map[string]string{"ep_append_failure": "escalation_policy_delete_audit_events", "key_append_failure": "integration_key_delete_audit_events", "cmnr_append_failure": "user_cmnr_delete_audit_events"}[mode]
				_, err = db.Exec(`CREATE FUNCTION sd5_append_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SYNTHETIC_SQL_DETAIL SYNTHETIC_CM@example.invalid'; END $$; CREATE TRIGGER sd5_append_fail BEFORE INSERT ON ` + table + ` FOR EACH ROW WHEN (NEW.record_kind='success_witness') EXECUTE FUNCTION sd5_append_fail()`)
				require.NoError(t, err)
			}
			var observed func()
			if strings.HasSuffix(mode, "append_failure") || mode == "earlier_group_failure" {
				observed = h.ExpectBackendError("deleteAll transaction failed")
			}
			response := stepOrganizationQuery(t, h, sd5Query([]string{root}, others...))
			if observed != nil {
				observed()
			}
			if mode == "all_success" || mode == "without_service" || mode == "ep_key" || mode == "ep_cmnr" {
				require.Empty(t, response.Errors)
				require.Equal(t, 1, sd5Count(t, h))
				serviceSuccess := 1
				if mode != "all_success" {
					serviceSuccess = 0
				}
				require.Equal(t, serviceSuccess, sd1Count(t, h, "committed"))
				var n int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM user_cmnr_delete_audit_events WHERE record_kind='success_witness'`).Scan(&n))
				wantCMNR := 2
				if mode == "ep_key" {
					wantCMNR = 0
				}
				require.Equal(t, wantCMNR, n)
				keySuccess := 0
				if mode == "without_service" || mode == "ep_key" {
					keySuccess = 1
				}
				require.Equal(t, keySuccess, sd4Count(t, h))
				require.Equal(t, 0, serviceManagementCount(t, h, "escalation_policy_steps", step))
			} else {
				require.NotEmpty(t, response.Errors)
				require.Zero(t, sd5Count(t, h))
				require.Zero(t, sd1Count(t, h, "committed"))
				require.Zero(t, sd4Count(t, h))
				require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policy_steps", step))
				require.Equal(t, 1, serviceManagementCount(t, h, "services", h.UUID("service-b")))
				require.Equal(t, 1, serviceManagementCount(t, h, "integration_keys", key.String()))
				if mode == "in_use" {
					var reason string
					require.NoError(t, db.QueryRow(`SELECT reason_code FROM escalation_policy_delete_audit_events LIMIT 1`).Scan(&reason))
					require.Equal(t, "target_in_use", reason)
				}
			}
			raw := sd5Rows(t, h) + sd1Rows(t, h) + cmnrAuditRows(t, h) + sd4Rows(t, h)
			require.NotContains(t, raw, "SYNTHETIC_")
			require.NotContains(t, raw, key.String())
		})
	}
}

func TestEscalationPolicyDeleteAuditControlledCommit(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"commit_then_error", "rollback_then_error", "completion_unknown", "begin_failed"} {
		t.Run(mode, func(t *testing.T) {
			h := sd1Harness(t)
			root := sd5EP(t, h, harness.SmokeOrganizationID)
			var database string
			require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&database))
			cfg, err := pgx.ParseConfig(harness.DBURL(database))
			require.NoError(t, err)
			connector := &serviceAuditFaultConnector{base: stdlib.GetConnector(*cfg), mode: mode}
			controlled := sql.OpenDB(connector)
			defer controlled.Close()
			controlled.SetMaxOpenConns(1)
			app := &graphqlapp.App{DB: controlled, PolicyStore: h.App().EscalationStore}
			ok, err := app.Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, root)})
			require.Error(t, err)
			require.False(t, ok)
			require.EqualValues(t, 2, connector.begins.Load())
			want := 0
			if mode == "commit_then_error" || mode == "completion_unknown" {
				want = 1
			}
			require.Equal(t, want, sd5Count(t, h))
			require.Equal(t, 1-want, serviceManagementCount(t, h, "escalation_policies", root))
			var outcome string
			require.NoError(t, h.App().DB().QueryRow(`SELECT outcome FROM escalation_policy_delete_audit_events WHERE record_kind='attempt_observation' LIMIT 1`).Scan(&outcome))
			if mode != "begin_failed" {
				require.Equal(t, "commit_unknown", outcome)
			}
		})
	}
}

func TestEscalationPolicyDeleteAuditRootLockWait(t *testing.T) {
	t.Parallel()
	h := sd1Harness(t)
	db := h.App().DB()
	root := sd5EP(t, h, harness.SmokeOrganizationID)
	conn, err := db.Conn(t.Context())
	require.NoError(t, err)
	defer conn.Close()
	tx, err := conn.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	var pid int
	require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
	_, err = tx.Exec(`SELECT id FROM escalation_policies WHERE id=$1 FOR UPDATE`, root)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(sd3System(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := sd5App(h).Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, root)})
		done <- err
	}()
	sd3WaitBlocked(t, db, pid)
	step := uuid.NewString()
	_, err = tx.Exec(`UPDATE escalation_policies SET organization_id=$2 WHERE id=$1`, root, h.UUID("org-b"))
	require.NoError(t, err)
	_, err = tx.Exec(`INSERT INTO escalation_policy_steps(id,escalation_policy_id) VALUES($1,$2)`, step, root)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	require.NoError(t, <-done)
	effects := sd5Effects(t, h, root)
	require.Len(t, effects, 1)
	require.Equal(t, step, effects[0].ResourceUUID.String())
	require.Equal(t, h.UUID("org-b"), effects[0].TargetOrganizationID.String())
}
