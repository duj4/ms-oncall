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
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
	audit "github.com/target/goalert/user/cmnrdeleteaudit"
	"github.com/target/goalert/user/contactmethod"
	"github.com/target/goalert/user/notificationrule"
)

func cmnrAuditRows(t *testing.T, h *harness.Harness) string {
	t.Helper()
	var rows string
	require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY event_id),'[]')::text FROM user_cmnr_delete_audit_events e`).Scan(&rows))
	return rows
}
func cmnrAuditCount(t *testing.T, h *harness.Harness, kind string) int {
	t.Helper()
	var n int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM user_cmnr_delete_audit_events WHERE record_kind=$1`, kind).Scan(&n))
	return n
}
func cmnrAuditQuery(cm, nr string) string {
	return fmt.Sprintf(`mutation{deleteAll(input:[{type:contactMethod,id:%q},{type:notificationRule,id:%q}])}`, cm, nr)
}

func TestCMNRDeleteAuditSignedHTTPB2AndHistory(t *testing.T) {
	for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN"} {
		for _, private := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/private_%t", role, private), func(t *testing.T) {
				h := cmnrHarness(t, true, role)
				f := cmnrSeed(t, h)
				db := h.App().DB()
				var isolation string
				require.NoError(t, db.QueryRow(`SHOW transaction_isolation`).Scan(&isolation))
				t.Log("actual isolation", isolation)
				_, err := db.Exec(`UPDATE user_contact_methods SET private=$2,name='SYNTHETIC_NAME_SECRET' WHERE id=$1`, f.cm[0], private)
				require.NoError(t, err)
				for delay := 1; delay <= 2; delay++ {
					_, err = db.Exec(`INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,$4)`, uuid.New(), cmnrUser("alice"), f.cm[0], delay)
					require.NoError(t, err)
				}
				var subjectID int64
				require.NoError(t, db.QueryRow(`INSERT INTO auth_subjects(provider_id,subject_id,user_id,cm_id) VALUES('SYNTHETIC_PROVIDER_SECRET','SYNTHETIC_SUBJECT_SECRET',$1,$2) RETURNING id`, cmnrUser("bob"), f.cm[0]).Scan(&subjectID))
				_, err = db.Exec(`UPDATE users SET alert_status_log_contact_method_id=$2 WHERE id=$1`, cmnrUser("alice"), f.cm[0])
				require.NoError(t, err)
				r := h.GraphQLQueryUserT(t, cmnrUser("alice"), cmnrAuditQuery(f.cm[0], f.nr[0]))
				require.Empty(t, r.Errors)
				require.JSONEq(t, `{"deleteAll":true}`, string(r.Data))
				require.Equal(t, 2, cmnrAuditCount(t, h, "success_witness"))
				var actor, home, target, owner string
				var effectsRaw, relatedRaw string
				require.NoError(t, db.QueryRow(`SELECT actor_id,home_organization_id,target_organization_id,root_owner_user_id,effects::text,related_explicit_events::text FROM user_cmnr_delete_audit_events WHERE root_type='contact_method'`).Scan(&actor, &home, &target, &owner, &effectsRaw, &relatedRaw))
				require.Equal(t, cmnrUser("alice"), actor)
				require.Equal(t, actor, owner)
				require.Equal(t, harness.SmokeOrganizationID, home)
				require.Equal(t, home, target)
				var effects []audit.Effect
				require.NoError(t, json.Unmarshal([]byte(effectsRaw), &effects))
				require.Len(t, effects, 4)
				counts := map[string]int{}
				for _, e := range effects {
					counts[e.ResourceType]++
					switch e.ResourceType {
					case "auth_subject":
						require.Equal(t, subjectID, *e.ResourceNumericID)
						require.Equal(t, cmnrUser("bob"), e.OwnerUserID.String())
						require.Equal(t, cmnrUser("org-b"), e.TargetOrganizationID.String())
					case "notification_rule":
						require.NotEqual(t, f.nr[0], e.ResourceUUID.String())
					}
				}
				require.Equal(t, map[string]int{"notification_rule": 2, "auth_subject": 1, "user_status_contact_setting": 1}, counts)
				var related []audit.RelatedExplicitEvent
				require.NoError(t, json.Unmarshal([]byte(relatedRaw), &related))
				require.Len(t, related, 1)
				var relatedRoot string
				require.NoError(t, db.QueryRow(`SELECT root_id FROM user_cmnr_delete_audit_events WHERE event_id=$1`, related[0].EventID).Scan(&relatedRoot))
				require.Equal(t, f.nr[0], relatedRoot)
				before := cmnrAuditRows(t, h)
				require.NotContains(t, before, "SYNTHETIC_")
				require.NotContains(t, before, "@example.invalid")
				// Delete the live owner/actor after the event. Historical snapshots and
				// related effects must remain byte-identical without live-resource FKs.
				_, err = db.Exec(`DELETE FROM users WHERE id=$1`, cmnrUser("alice"))
				require.NoError(t, err)
				require.Equal(t, before, cmnrAuditRows(t, h))
			})
		}
	}
}

func TestCMNRDeleteAuditPlatformAttributionAndMixedTransaction(t *testing.T) {
	for _, home := range []string{"ORG_MEMBER", "ORG_ADMIN", "DEFAULT"} {
		t.Run(home, func(t *testing.T) {
			h := cmnrPlatformHarness(t, "ORG_MEMBER")
			f := cmnrSeed(t, h)
			db := h.App().DB()
			if home == "DEFAULT" {
				_, err := db.Exec(`UPDATE user_organization_assignments SET effective_organization_id=$2,effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, harness.DefaultGraphQLAdminUserID, organization.DefaultOrganizationID)
				require.NoError(t, err)
			} else {
				_, err := db.Exec(`UPDATE user_organization_assignments SET organization_role=$2 WHERE user_id=$1`, harness.DefaultGraphQLAdminUserID, home)
				require.NoError(t, err)
			}
			ep, svc := uuid.NewString(), uuid.NewString()
			_, err := db.Exec(`INSERT INTO escalation_policies(id,name,organization_id) VALUES($1,'SD2 policy',$2)`, ep, harness.SmokeOrganizationID)
			require.NoError(t, err)
			_, err = db.Exec(`INSERT INTO services(id,name,escalation_policy_id,organization_id) VALUES($1,'SD2 service',$2,$3)`, svc, ep, harness.SmokeOrganizationID)
			require.NoError(t, err)
			q := fmt.Sprintf(`mutation{deleteAll(input:[{type:contactMethod,id:%q},{type:notificationRule,id:%q},{type:contactMethod,id:%q},{type:service,id:%q}])}`, f.cm[3], f.nr[1], f.cm[0], svc)
			r := h.GraphQLQueryUserT(t, harness.DefaultGraphQLAdminUserID, q)
			require.Empty(t, r.Errors)
			require.Equal(t, 3, cmnrAuditCount(t, h, "success_witness"))
			var actors, attempts, requests, executions int
			require.NoError(t, db.QueryRow(`SELECT count(DISTINCT actor_id),count(DISTINCT attempt_id),count(DISTINCT request_id),count(DISTINCT execution_id) FROM user_cmnr_delete_audit_events`).Scan(&actors, &attempts, &requests, &executions))
			require.Equal(t, []int{1, 1, 1, 1}, []int{actors, attempts, requests, executions})
			var same bool
			require.NoError(t, db.QueryRow(`SELECT bool_and(s.attempt_id=c.attempt_id AND s.request_id=c.request_id) FROM service_delete_audit_events s CROSS JOIN user_cmnr_delete_audit_events c`).Scan(&same))
			require.True(t, same)
			var actor, actorHome, owner, target, role string
			require.NoError(t, db.QueryRow(`SELECT actor_id,home_organization_id,root_owner_user_id,target_organization_id,organization_role FROM user_cmnr_delete_audit_events WHERE root_id=$1`, f.cm[3]).Scan(&actor, &actorHome, &owner, &target, &role))
			require.Equal(t, harness.DefaultGraphQLAdminUserID, actor)
			require.Equal(t, cmnrUser("bob"), owner)
			require.Equal(t, cmnrUser("org-b"), target)
			if home == "DEFAULT" {
				require.Equal(t, organization.DefaultOrganizationID, actorHome)
				require.Equal(t, "NONE", role)
			} else {
				require.Equal(t, harness.SmokeOrganizationID, actorHome)
				require.Equal(t, home, role)
			}
		})
	}
}

func TestCMNRDeleteAuditRollbackFailureAndMissingSchema(t *testing.T) {
	for _, mode := range []string{"audit", "all_audit", "schema", "rejected", "retry", "later_group"} {
		t.Run(mode, func(t *testing.T) {
			h := cmnrHarness(t, true, "ORG_MEMBER")
			h.IgnoreErrorsWith("cmnr.delete audit persistence unavailable")
			h.IgnoreErrorsWith("deleteAll transaction failed")
			f := cmnrSeed(t, h)
			db := h.App().DB()
			before := cmnrSnapshot(t, db)
			switch mode {
			case "audit", "all_audit":
				condition := "NEW.record_kind='success_witness'"
				if mode == "all_audit" {
					condition = "true"
				}
				_, err := db.Exec(`CREATE FUNCTION sd2_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF ` + condition + ` THEN RAISE EXCEPTION 'SYNTHETIC_AUDIT_SECRET'; END IF; RETURN NEW; END $$; CREATE TRIGGER sd2_fault BEFORE INSERT ON user_cmnr_delete_audit_events FOR EACH ROW EXECUTE FUNCTION sd2_fault()`)
				require.NoError(t, err)
			case "schema":
				_, err := db.Exec(`ALTER TABLE user_cmnr_delete_audit_events RENAME TO sd2_absent`)
				require.NoError(t, err)
			case "rejected":
				_, err := db.Exec(`CREATE FUNCTION sd2_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='SYNTHETIC_COMMIT_SECRET'; END $$; CREATE CONSTRAINT TRIGGER sd2_reject AFTER DELETE ON user_contact_methods DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sd2_reject()`)
				require.NoError(t, err)
				t.Cleanup(func() { _, err := db.Exec(`DROP TRIGGER sd2_reject ON user_contact_methods`); require.NoError(t, err) })
			case "retry":
				_, err := db.Exec(`CREATE SEQUENCE sd2_retry; CREATE FUNCTION sd2_retry() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF nextval('sd2_retry')<=2 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='SYNTHETIC_RETRY_SECRET'; END IF; RETURN OLD; END $$; CREATE TRIGGER sd2_retry BEFORE DELETE ON user_contact_methods FOR EACH ROW EXECUTE FUNCTION sd2_retry()`)
				require.NoError(t, err)
			}
			q := cmnrAuditQuery(f.cm[0], f.nr[0])
			if mode == "later_group" {
				q = fmt.Sprintf(`mutation{deleteAll(input:[{type:contactMethod,id:%q},{type:notificationRule,id:%q},{type:userSession,id:"not-a-uuid"}])}`, f.cm[0], f.nr[0])
			}
			r := h.GraphQLQueryUserT(t, cmnrUser("alice"), q)
			require.NotContains(t, fmt.Sprint(r), "SYNTHETIC_")
			if len(r.Errors) > 0 {
				t.Log("expected safe rejection:", r.Errors[0].Message)
			}
			if mode == "retry" {
				require.Empty(t, r.Errors)
				require.Equal(t, 2, cmnrAuditCount(t, h, "success_witness"))
				var attempts, executions, requests int
				require.NoError(t, db.QueryRow(`SELECT count(DISTINCT attempt_id),count(DISTINCT execution_id),count(DISTINCT request_id) FROM user_cmnr_delete_audit_events`).Scan(&attempts, &executions, &requests))
				require.Equal(t, []int{3, 1, 1}, []int{attempts, executions, requests})
			} else {
				require.NotEmpty(t, r.Errors)
				require.Equal(t, before, cmnrSnapshot(t, db))
				if mode != "schema" {
					require.Zero(t, cmnrAuditCount(t, h, "success_witness"))
					if mode != "all_audit" {
						require.Greater(t, cmnrAuditCount(t, h, "attempt_observation"), 0)
					}
				}
			}
			if mode != "schema" {
				require.NotContains(t, cmnrAuditRows(t, h), "SYNTHETIC_")
			}
		})
	}
}

func TestCMNRDeleteAuditLateExplicitCascade(t *testing.T) {
	h := cmnrPlatformHarness(t, "ORG_MEMBER")
	f := cmnrSeed(t, h)
	db := h.App().DB()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	blocker, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer blocker.Rollback()
	var pid int
	require.NoError(t, blocker.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	_, err = blocker.ExecContext(ctx, `SELECT id FROM user_contact_methods WHERE id=$1 FOR UPDATE`, f.cm[0])
	require.NoError(t, err)
	late := uuid.NewString()
	human := cmnrPlatformHuman(t, h, harness.DefaultGraphQLAdminUserID)
	cmStore, err := newCMNRAuditStores(t, h)
	require.NoError(t, err)
	app := &graphqlapp.App{DB: db, CMStore: cmStore.cm, NRStore: cmStore.nr}
	done := make(chan error, 1)
	go func() {
		_, err := app.Mutation().DeleteAll(human, []assignment.RawTarget{{Type: assignment.TargetTypeNotificationRule, ID: late}, {Type: assignment.TargetTypeContactMethod, ID: f.cm[0]}})
		done <- err
	}()
	waited := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		err = db.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid))`, pid).Scan(&n)
		if err != nil || n > 0 {
			waited = n > 0
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, insertErr := blocker.ExecContext(ctx, `INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,8)`, late, cmnrUser("alice"), f.cm[0])
	_, subjectErr := blocker.ExecContext(ctx, `INSERT INTO auth_subjects(provider_id,subject_id,user_id,cm_id) VALUES('sd2-concurrent','SYNTHETIC_CONCURRENT_SUBJECT',$1,$2)`, cmnrUser("bob"), f.cm[0])
	_, settingErr := blocker.ExecContext(ctx, `UPDATE users SET alert_status_log_contact_method_id=$2 WHERE id=$1`, cmnrUser("alice"), f.cm[0])
	_, assignmentErr := blocker.ExecContext(ctx, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, cmnrUser("alice"), cmnrUser("org-b"))
	commitErr := blocker.Commit()
	workerErr := <-done
	require.True(t, waited)
	require.NoError(t, insertErr)
	require.NoError(t, subjectErr)
	require.NoError(t, settingErr)
	require.NoError(t, assignmentErr)
	require.NoError(t, commitErr)
	require.NoError(t, workerErr)
	var mechanism, cause, parent string
	require.NoError(t, db.QueryRow(`SELECT deletion_mechanism,cause_event_id,parent_cm_id FROM user_cmnr_delete_audit_events WHERE root_id=$1`, late).Scan(&mechanism, &cause, &parent))
	require.Equal(t, "fk_cascade", mechanism)
	require.Equal(t, f.cm[0], parent)
	var linked bool
	require.NoError(t, db.QueryRow(`SELECT related_explicit_events @> jsonb_build_array(jsonb_build_object('event_id',(SELECT event_id FROM user_cmnr_delete_audit_events WHERE root_id=$1),'relation','parent_cm')) FROM user_cmnr_delete_audit_events WHERE event_id=$2`, late, cause).Scan(&linked))
	require.True(t, linked)
	var home, target string
	var effects int
	require.NoError(t, db.QueryRow(`SELECT home_organization_id,target_organization_id,jsonb_array_length(effects) FROM user_cmnr_delete_audit_events WHERE event_id=$1`, cause).Scan(&home, &target, &effects))
	require.Equal(t, harness.SmokeOrganizationID, home)
	require.Equal(t, cmnrUser("org-b"), target)
	require.Equal(t, 3, effects, "fresh NR, Subject and setting snapshots after the observed parent lock wait")
}

func TestCMNRDeleteAuditMixedFailureAtomicity(t *testing.T) {
	for _, table := range []string{"service_delete_audit_events", "user_cmnr_delete_audit_events"} {
		t.Run(table, func(t *testing.T) {
			h := cmnrPlatformHarness(t, "ORG_MEMBER")
			h.IgnoreErrorsWith("deleteAll transaction failed")
			f := cmnrSeed(t, h)
			db := h.App().DB()
			before := cmnrSnapshot(t, db)
			ep, svc := uuid.NewString(), uuid.NewString()
			_, err := db.Exec(`INSERT INTO escalation_policies(id,name,organization_id) VALUES($1,'SD2 mixed policy',$2)`, ep, harness.SmokeOrganizationID)
			require.NoError(t, err)
			_, err = db.Exec(`INSERT INTO services(id,name,escalation_policy_id,organization_id) VALUES($1,'SD2 mixed service',$2,$3)`, svc, ep, harness.SmokeOrganizationID)
			require.NoError(t, err)
			_, err = db.Exec(`CREATE FUNCTION sd2_mixed_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome='committed' THEN RAISE EXCEPTION 'SYNTHETIC_MIXED_SECRET'; END IF; RETURN NEW; END $$; CREATE TRIGGER sd2_mixed_fault BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION sd2_mixed_fault()`)
			require.NoError(t, err)
			q := fmt.Sprintf(`mutation{deleteAll(input:[{type:service,id:%q},{type:contactMethod,id:%q},{type:notificationRule,id:%q}])}`, svc, f.cm[0], f.nr[0])
			r := h.GraphQLQueryUserT(t, harness.DefaultGraphQLAdminUserID, q)
			require.NotEmpty(t, r.Errors)
			require.Equal(t, before, cmnrSnapshot(t, db))
			require.Zero(t, cmnrAuditCount(t, h, "success_witness"))
			var services, successes, observations int
			require.NoError(t, db.QueryRow(`SELECT (SELECT count(*) FROM services WHERE id=$1),(SELECT count(*) FROM service_delete_audit_events WHERE outcome='committed'),(SELECT count(*) FROM service_delete_audit_events WHERE reason_code='audit_write_failed')`, svc).Scan(&services, &successes, &observations))
			require.Equal(t, 1, services)
			require.Zero(t, successes)
			require.Equal(t, 1, observations)
			require.Equal(t, 2, cmnrAuditCount(t, h, "attempt_observation"))
			var same bool
			require.NoError(t, db.QueryRow(`SELECT bool_and(s.attempt_id=c.attempt_id AND s.request_id=c.request_id AND s.outcome=c.outcome AND c.reason_code='audit_write_failed') FROM service_delete_audit_events s CROSS JOIN user_cmnr_delete_audit_events c`).Scan(&same))
			require.True(t, same)
		})
	}
}

func TestCMNRDeleteAuditStoreOwnershipAndNoop(t *testing.T) {
	h := cmnrHarness(t, true, "ORG_MEMBER")
	f := cmnrSeed(t, h)
	db := h.App().DB()
	stores, err := newCMNRAuditStores(t, h)
	require.NoError(t, err)
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	result, err := stores.cm.DeleteForAuditTx(cmnrHuman(t, h, "alice"), tx, f.cm[0], f.cm[0], uuid.NewString())
	require.NoError(t, err)
	require.Len(t, result.Targets, 1)
	require.True(t, result.Targets[0].Deleted)
	require.NoError(t, tx.Rollback())
	require.Zero(t, cmnrAuditCount(t, h, "success_witness"))
	for _, ids := range [][]string{nil, {uuid.NewString()}, {f.cm[0], f.cm[0]}} {
		var input []string
		for _, id := range ids {
			input = append(input, fmt.Sprintf(`{type:contactMethod,id:%q}`, id))
		}
		r := h.GraphQLQueryUserT(t, cmnrUser("alice"), `mutation{deleteAll(input:[`+strings.Join(input, ",")+`])}`)
		require.Empty(t, r.Errors)
	}
	require.Equal(t, 1, cmnrAuditCount(t, h, "success_witness"))
	q := strings.Repeat(fmt.Sprintf(`{type:contactMethod,id:%q},`, f.cm[1]), 51)
	r := h.GraphQLQueryUserT(t, cmnrUser("alice"), `mutation{deleteAll(input:[`+q+`])}`)
	require.NotEmpty(t, r.Errors)
	// Source-less legacy callers keep their original unaudited Store path.
	err = stores.cm.Delete(permission.UserContext(t.Context(), cmnrUser("alice"), permission.RoleUser), db, f.cm[1])
	require.NoError(t, err)
	require.Equal(t, 1, cmnrAuditCount(t, h, "success_witness"))
	var count int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM user_contact_methods WHERE id=$1`, f.cm[1]).Scan(&count))
	require.Zero(t, count)
}

// These constructors use the production Stores, with no backend/interface mock.
type cmnrAuditStores struct {
	cm *contactmethod.Store
	nr *notificationrule.Store
}

func newCMNRAuditStores(t *testing.T, h *harness.Harness) (cmnrAuditStores, error) {
	t.Helper()
	return cmnrAuditStores{h.App().ContactMethodStore, h.App().NotificationRuleStore}, nil
}

func TestCMNRDeleteAuditCapacityFailsClosed(t *testing.T) {
	h := cmnrHarness(t, true, "ORG_MEMBER")
	h.IgnoreErrorsWith("deleteAll transaction failed")
	f := cmnrSeed(t, h)
	db := h.App().DB()
	_, err := db.Exec(`INSERT INTO auth_subjects(provider_id,subject_id,user_id,cm_id) SELECT 'sd2-capacity',g::text,$1,$2 FROM generate_series(1,$3) g`, cmnrUser("alice"), f.cm[0], audit.MaxEffects+1)
	require.NoError(t, err)
	r := h.GraphQLQueryUserT(t, cmnrUser("alice"), fmt.Sprintf(`mutation{deleteAll(input:[{type:contactMethod,id:%q}])}`, f.cm[0]))
	require.NotEmpty(t, r.Errors)
	var roots, subjects int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM user_contact_methods WHERE id=$1`, f.cm[0]).Scan(&roots))
	require.Equal(t, 1, roots)
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_subjects WHERE cm_id=$1`, f.cm[0]).Scan(&subjects))
	require.Equal(t, audit.MaxEffects+1, subjects)
	require.Zero(t, cmnrAuditCount(t, h, "success_witness"))
	var reason string
	require.NoError(t, db.QueryRow(`SELECT reason_code FROM user_cmnr_delete_audit_events`).Scan(&reason))
	require.Equal(t, "audit_write_failed", reason)
	// Bring the total to exactly MaxEffects (one NR plus MaxEffects-1
	// Subjects), then prove complete serialization and atomic persistence.
	_, err = db.Exec(`DELETE FROM auth_subjects WHERE id IN (SELECT id FROM auth_subjects WHERE cm_id=$1 ORDER BY id LIMIT 2)`, f.cm[0])
	require.NoError(t, err)
	r = h.GraphQLQueryUserT(t, cmnrUser("alice"), fmt.Sprintf(`mutation{deleteAll(input:[{type:contactMethod,id:%q}])}`, f.cm[0]))
	require.Empty(t, r.Errors)
	var effects, bytes int
	require.NoError(t, db.QueryRow(`SELECT jsonb_array_length(effects),octet_length(effects::text) FROM user_cmnr_delete_audit_events WHERE record_kind='success_witness'`).Scan(&effects, &bytes))
	require.Equal(t, audit.MaxEffects, effects)
	require.Less(t, bytes, audit.MaxJSONBytes)
	t.Log("complete boundary witness effects/JSONB text bytes", effects, bytes)
}

func TestCMNRDeleteAuditUserFirstSystemAndSuppressedDelete(t *testing.T) {
	for _, mode := range []string{"UserFirst", "SystemUnknownOrg", "Suppressed"} {
		t.Run(mode, func(t *testing.T) {
			h := cmnrPlatformHarness(t, "ORG_MEMBER")
			f := cmnrSeed(t, h)
			db := h.App().DB()
			switch mode {
			case "UserFirst":
				q := fmt.Sprintf(`mutation{deleteAll(input:[{type:contactMethod,id:%q},{type:notificationRule,id:%q},{type:user,id:%q}])}`, f.cm[3], f.nr[3], cmnrUser("bob"))
				r := h.GraphQLQueryUserT(t, harness.DefaultGraphQLAdminUserID, q)
				require.Empty(t, r.Errors)
				require.Zero(t, cmnrAuditCount(t, h, "success_witness"))
			case "SystemUnknownOrg":
				_, err := db.Exec(`DELETE FROM user_organization_assignments WHERE user_id=$1`, cmnrUser("alice"))
				require.NoError(t, err)
				app := &graphqlapp.App{DB: db, CMStore: h.App().ContactMethodStore, NRStore: h.App().NotificationRuleStore}
				ok, err := app.Mutation().DeleteAll(permission.SystemContext(t.Context(), "Engine"), []assignment.RawTarget{{Type: assignment.TargetTypeContactMethod, ID: f.cm[0]}})
				require.NoError(t, err)
				require.True(t, ok)
				var kind, resolution string
				var actor, home, org sql.NullString
				require.NoError(t, db.QueryRow(`SELECT actor_kind,actor_id,home_organization_id,target_organization_id,target_org_resolution FROM user_cmnr_delete_audit_events`).Scan(&kind, &actor, &home, &org, &resolution))
				require.Equal(t, "internal_system", kind)
				require.Equal(t, "unknown", resolution)
				require.False(t, actor.Valid || home.Valid || org.Valid)
			case "Suppressed":
				_, err := db.Exec(`CREATE FUNCTION sd2_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$; CREATE TRIGGER sd2_suppress BEFORE DELETE ON user_contact_methods FOR EACH ROW EXECUTE FUNCTION sd2_suppress()`)
				require.NoError(t, err)
				tx, err := db.BeginTx(t.Context(), nil)
				require.NoError(t, err)
				result, err := h.App().ContactMethodStore.DeleteForAuditTx(cmnrHuman(t, h, "alice"), tx, f.cm[0])
				require.NoError(t, err)
				require.Len(t, result.Targets, 1)
				require.False(t, result.Targets[0].Deleted)
				require.NoError(t, tx.Rollback())
				r := h.GraphQLQueryUserT(t, cmnrUser("alice"), fmt.Sprintf(`mutation{deleteAll(input:[{type:contactMethod,id:%q}])}`, f.cm[0]))
				require.Empty(t, r.Errors)
				require.Zero(t, cmnrAuditCount(t, h, "success_witness"))
			}
		})
	}
}

func TestCMNRDeleteAuditControlledAcknowledgementsOverPostgres(t *testing.T) {
	for _, mode := range []string{"commit_then_error", "rollback_then_error", "completion_unknown", "begin_failed"} {
		t.Run(mode, func(t *testing.T) {
			h := cmnrHarness(t, true, "ORG_MEMBER")
			f := cmnrSeed(t, h)
			db := h.App().DB()
			var name string
			require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&name))
			cfg, err := pgx.ParseConfig(harness.DBURL(name))
			require.NoError(t, err)
			connector := &serviceAuditFaultConnector{base: stdlib.GetConnector(*cfg), mode: mode}
			controlled := sql.OpenDB(connector)
			controlled.SetMaxOpenConns(1)
			defer controlled.Close()
			app := &graphqlapp.App{DB: controlled, CMStore: h.App().ContactMethodStore, NRStore: h.App().NotificationRuleStore}
			ok, err := app.Mutation().DeleteAll(cmnrHuman(t, h, "alice"), []assignment.RawTarget{{Type: assignment.TargetTypeContactMethod, ID: f.cm[0]}, {Type: assignment.TargetTypeNotificationRule, ID: f.nr[0]}})
			require.Error(t, err)
			require.False(t, ok)
			require.NotContains(t, err.Error(), "SYNTHETIC_")
			require.EqualValues(t, 2, connector.begins.Load(), "one business Begin and one failure transaction, never an unknown replay")
			want := 0
			if mode == "commit_then_error" || mode == "completion_unknown" {
				want = 2
			}
			require.Equal(t, want, cmnrAuditCount(t, h, "success_witness"))
			var roots int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM user_contact_methods WHERE id=$1`, f.cm[0]).Scan(&roots))
			if want > 0 {
				require.Zero(t, roots)
			} else {
				require.Equal(t, 1, roots)
			}
			var outcomes string
			require.NoError(t, db.QueryRow(`SELECT string_agg(DISTINCT outcome,',') FROM user_cmnr_delete_audit_events WHERE record_kind='attempt_observation'`).Scan(&outcomes))
			if mode == "begin_failed" {
				require.Equal(t, "tx_failed", outcomes)
			} else {
				require.Equal(t, "commit_unknown", outcomes)
			}
			t.Log("controlled driver around PostgreSQL, not a native crash/network test:", mode)
		})
	}
}

func TestCMNRDeleteAuditWitnessVisibility(t *testing.T) {
	h := cmnrHarness(t, true, "ORG_MEMBER")
	f := cmnrSeed(t, h)
	db := h.App().DB()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	blocker, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer blocker.Rollback()
	var pid int
	require.NoError(t, blocker.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	_, err = blocker.ExecContext(ctx, `LOCK TABLE user_cmnr_delete_audit_events IN SHARE MODE`)
	require.NoError(t, err)
	app := &graphqlapp.App{DB: db, CMStore: h.App().ContactMethodStore, NRStore: h.App().NotificationRuleStore}
	human := cmnrHuman(t, h, "alice")
	done := make(chan error, 1)
	go func() {
		_, err := app.Mutation().DeleteAll(human, []assignment.RawTarget{{Type: assignment.TargetTypeContactMethod, ID: f.cm[0]}, {Type: assignment.TargetTypeNotificationRule, ID: f.nr[0]}})
		done <- err
	}()
	waited := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		err = db.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%INSERT INTO user_cmnr_delete_audit_events%'`, pid).Scan(&n)
		if err != nil || n > 0 {
			waited = n > 0
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var roots, witnesses int
	readErr := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM user_contact_methods WHERE id=$1),(SELECT count(*) FROM user_cmnr_delete_audit_events)`, f.cm[0]).Scan(&roots, &witnesses)
	releaseErr := blocker.Rollback()
	workerErr := <-done
	require.True(t, waited, "observe real PG wait at audit INSERT")
	require.NoError(t, readErr)
	require.Equal(t, 1, roots)
	require.Zero(t, witnesses)
	require.NoError(t, releaseErr)
	require.NoError(t, workerErr)
	require.Equal(t, 2, cmnrAuditCount(t, h, "success_witness"))
}
