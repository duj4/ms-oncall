package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/graphql2"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/user/contactmethod"
)

func cmRoot(id uuid.UUID) ds.Resource {
	return ds.Resource{Kind: ds.ResourceContactMethod, ID: id.String()}
}
func cmSelectors(ids ...uuid.UUID) []collector.Selector {
	out := make([]collector.Selector, len(ids))
	for i, id := range ids {
		out[i] = collector.Selector{Kind: ds.ResourceContactMethod, ID: id.String()}
	}
	return out
}
func cmInput(ids ...uuid.UUID) []assignment.RawTarget {
	out := make([]assignment.RawTarget, len(ids))
	for i, id := range ids {
		out[i] = assignment.RawTarget{Type: assignment.TargetTypeContactMethod, ID: id.String()}
	}
	return out
}
func cmVersion(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	facts, err := collectDeletion(t, ctx, db, cmRoot(id), collector.Limits{})
	require.NoError(t, err)
	return deletionPlan(t, cmRoot(id), facts).ImpactVersion()
}
func cmEnforce(t *testing.T, ctx context.Context, tx *sql.Tx, id uuid.UUID, version string) context.Context {
	t.Helper()
	bound, err := collector.Enforce(ctx, tx, cmSelectors(id), version, true, authorizeDeletionFixture(cmRoot(id)))
	require.NoError(t, err)
	return bound
}
func cmInsert(t *testing.T, ctx context.Context, db *sql.DB, id, owner uuid.UUID) {
	t.Helper()
	enforcementExec(t, ctx, db, `INSERT INTO user_contact_methods(id,user_id,name,type,value,dest,pending) VALUES($1,$2,($1::uuid)::text,'WEBHOOK',($1::uuid)::text,jsonb_build_object('type','synthetic','id',($1::uuid)::text),false)`, id, owner)
}

func TestPostgresDeletionEnforcementCMBusiness(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "CMProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, count := range []int{0, 1, 3} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := newDeletionFixture(t, ctx, db)
			otherCM, otherNR := nrSibling(t, ctx, db, f, 0)
			if count == 0 {
				enforcementExec(t, ctx, db, `DELETE FROM user_notification_rules WHERE id=$1`, f.nr)
			}
			for i := 1; i < count; i++ {
				enforcementExec(t, ctx, db, `INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3)`, f.user, f.cm, i)
			}
			before := enforcementCount(t, ctx, db, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE outcome='committed'`)
			require.Contains(t, enforcementHTTP(t, ctx, app, cmInput(f.cm), nil, true), string(ds.DeletionConfirmationRequired))
			confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeContactMethod, ID: f.cm.String()})
			stale := *confirm
			stale.ExpectedImpactVersion = "stale"
			_, err := app.Mutation().DeleteAll(ctx, cmInput(f.cm), &stale)
			enforceCode(t, err, ds.DeletionDependencyChanged)
			ok, err := app.Mutation().DeleteAll(ctx, cmInput(f.cm), confirm)
			require.NoError(t, err)
			require.True(t, ok)
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, f.cm))
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE contact_method_id=$1`, f.cm))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, otherCM))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, otherNR))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE outcome='committed' AND root_id=$1 AND root_type='contact_method' AND provenance='EXPLICIT'`, f.cm))
			require.Equal(t, count, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_cmnr_delete_audit_events a CROSS JOIN LATERAL jsonb_array_elements(a.effects) e WHERE a.outcome='committed' AND a.root_id=$1 AND e->>'resource_type'='notification_rule' AND e->>'provenance'='IMPLICIT_FK_CASCADE'`, f.cm))
			require.Equal(t, before+1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE outcome='committed'`))
			ok, err = app.Mutation().DeleteAll(ctx, cmInput(f.cm), nil)
			require.NoError(t, err)
			require.True(t, ok)
			_, err = app.Mutation().DeleteAll(ctx, cmInput(f.cm), confirm)
			enforceCode(t, err, ds.DeletionDependencyChanged)
		})
	}
	f := newDeletionFixture(t, ctx, db)
	second, _ := nrSibling(t, ctx, db, f, 3)
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeContactMethod, ID: f.cm.String()}, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeContactMethod, ID: second.String()})
	ok, err := app.Mutation().DeleteAll(ctx, cmInput(f.cm, f.cm, second, uuid.New()), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_cmnr_delete_audit_events a CROSS JOIN LATERAL jsonb_array_elements(a.effects) e WHERE a.outcome='committed' AND e->>'resource_type'='notification_rule' AND (a.root_id=$1 OR a.root_id=$2)`, f.cm, second))
	raw := make([]assignment.RawTarget, 51)
	for i := range raw {
		raw[i] = cmInput(uuid.New())[0]
	}
	_, err = app.Mutation().DeleteAll(ctx, raw, nil)
	require.Error(t, err)
	require.NotEqual(t, string(ds.DeletionUnavailable), err.Error())
	_, err = app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeContactMethod, ID: "invalid"}}, nil)
	require.Error(t, err)
}

func TestPostgresDeletionEnforcementCMRelationships(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "CMProfileTest")
	app := enforcementApp(t, ctx, db)
	f := newDeletionFixture(t, ctx, db)
	code, msg := uuid.New(), uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO user_verification_codes(id,contact_method_id,code,expires_at) VALUES($1,$2,123456,now()+'10 minutes'::interval)`, code, f.cm)
	enforcementExec(t, ctx, db, `INSERT INTO outgoing_messages(id,user_id,contact_method_id,user_verification_code_id,message_type) VALUES($1,$2,$3,$4,'verification_message')`, msg, f.user, f.cm, code)
	enforcementExec(t, ctx, db, `INSERT INTO alert_status_subscriptions(contact_method_id,alert_id,last_alert_status) VALUES($1,$2,'triggered')`, f.cm, f.active)
	enforcementExec(t, ctx, db, `UPDATE users SET alert_status_log_contact_method_id=$2 WHERE id=$1`, f.user, f.cm)
	enforcementExec(t, ctx, db, `INSERT INTO pending_signals(service_id,dest_id,message_id,params) VALUES($1,$2,$3,'{}')`, f.service, f.channel, msg)
	facts, err := collectDeletion(t, ctx, db, cmRoot(f.cm), collector.Limits{})
	require.NoError(t, err)
	rels := map[ds.RelationshipKind]bool{}
	for _, d := range facts.Collection.Dependencies {
		rels[d.Relationship] = true
	}
	for _, r := range []ds.RelationshipKind{ds.RelationshipVerification, ds.RelationshipOutgoingMessage, ds.RelationshipMessageStatus, ds.RelationshipContactSubscription, ds.RelationshipContactAuthSubject, ds.RelationshipStatusContact, ds.RelationshipPendingSignal} {
		require.True(t, rels[r], "relationship %v", r)
	}
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeContactMethod, ID: f.cm.String()})
	ok, err := app.Mutation().DeleteAll(ctx, cmInput(f.cm), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	for _, q := range []string{`SELECT count(*) FROM user_verification_codes WHERE contact_method_id=$1`, `SELECT count(*) FROM outgoing_messages WHERE contact_method_id=$1`, `SELECT count(*) FROM alert_status_subscriptions WHERE contact_method_id=$1`, `SELECT count(*) FROM auth_subjects WHERE cm_id=$1`, `SELECT count(*) FROM users WHERE alert_status_log_contact_method_id=$1`} {
		require.Zero(t, enforcementCount(t, ctx, db, q, f.cm))
	}
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM pending_signals WHERE message_id=$1`, msg))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM message_status_history WHERE message_id=$1`, msg))
	require.Equal(t, 3, enforcementCount(t, ctx, db, `SELECT count(*) FROM notification_policy_cycles WHERE user_id=$1`, f.user))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM alerts WHERE id=$1 AND status='triggered'`, f.active))
	// The existing B2 effects retain the auth-subject delete and status-setting clear.
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_cmnr_delete_audit_events a CROSS JOIN LATERAL jsonb_array_elements(a.effects) e WHERE a.outcome='committed' AND e->>'resource_type' IN ('auth_subject','user_status_contact_setting')`))
}

func TestPostgresDeletionEnforcementCMUnsupported(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "CMProfileTest")
	app := enforcementApp(t, ctx, db)
	f := newDeletionFixture(t, ctx, db)
	for _, batch := range [][]assignment.RawTarget{append(cmInput(f.cm), nrInput(f.nr)...), append(cmInput(f.cm), assignment.RawTarget{Type: assignment.TargetTypeUser, ID: f.user.String()}), append(cmInput(f.cm), assignment.RawTarget{Type: assignment.TargetTypeService, ID: f.service.String()})} {
		_, err := app.Mutation().DeleteAll(ctx, batch, nil)
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	enforcementExec(t, ctx, db, `UPDATE outgoing_messages SET status_alert_ids=ARRAY[$2::bigint] WHERE contact_method_id=$1`, f.cm, f.active)
	_, err := app.Mutation().DeleteAll(ctx, cmInput(f.cm), nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, f.cm))
	nrNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementCMMissingWindow(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "CMProfileTest")
	f := newDeletionFixture(t, ctx, db)
	other := newDeletionFixture(t, ctx, db)
	store := contactmethod.NewStore(nil)
	app := enforcementApp(t, ctx, db)
	ok, err := app.Mutation().DeleteAll(ctx, cmInput(uuid.Nil), nil)
	require.NoError(t, err)
	require.True(t, ok)
	for _, legacy := range []bool{false, true} {
		id := uuid.New()
		tx := nrBegin(t, ctx, db)
		carrier, err := collector.Enforce(ctx, tx, cmSelectors(id), "", false, authorizeDeletionFixture(cmRoot(id)))
		require.NoError(t, err)
		cmInsert(t, ctx, db, id, other.user)
		nr := uuid.New()
		enforcementExec(t, ctx, db, `INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,8)`, nr, other.user, id)
		if legacy {
			require.NoError(t, store.Delete(carrier, tx, id.String()))
		} else {
			result, err := store.DeleteForAuditTx(carrier, tx, id.String())
			require.NoError(t, err)
			require.Empty(t, result.Targets)
			require.Empty(t, result.CascadeRules)
		}
		require.NoError(t, tx.Commit())
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, nr))
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, id))
	}
	id := uuid.New()
	version := cmVersion(t, ctx, db, f.cm)
	tx := nrBegin(t, ctx, db)
	carrier, err := collector.Enforce(ctx, tx, cmSelectors(f.cm, id), version, true, authorizeDeletionFixture(cmRoot(f.cm)))
	require.NoError(t, err)
	cmInsert(t, ctx, db, id, other.user)
	enforcementExec(t, ctx, db, `INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES($1,$2,9)`, other.user, id)
	result, err := store.DeleteForAuditTx(carrier, tx, f.cm.String(), id.String())
	require.NoError(t, err)
	require.Len(t, result.Targets, 1)
	require.Equal(t, f.cm, result.Targets[0].ID)
	require.Len(t, result.CascadeRules, 1)
	require.Equal(t, f.nr, result.CascadeRules[0].ID)
	require.NoError(t, tx.Commit())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, id))
	tx = nrBegin(t, ctx, db)
	_, err = collector.Enforce(ctx, tx, cmSelectors(f.cm), version, true, authorizeDeletionFixture(cmRoot(f.cm)))
	enforceCode(t, err, ds.DeletionDependencyChanged)
	require.NoError(t, tx.Rollback())
	nrNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementCMAuditFailure(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "CMProfileTest")
	f := newDeletionFixture(t, ctx, db)
	app := enforcementApp(t, ctx, db)
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeContactMethod, ID: f.cm.String()})
	enforcementExec(t, ctx, db, `CREATE FUNCTION synthetic_cm_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome='committed' THEN RAISE EXCEPTION 'SYNTHETIC_PRIVATE_AUDIT'; END IF; RETURN NEW; END $$`)
	enforcementExec(t, ctx, db, `CREATE TRIGGER synthetic_cm_audit_failure BEFORE INSERT ON user_cmnr_delete_audit_events FOR EACH ROW EXECUTE FUNCTION synthetic_cm_audit_failure()`)
	before := deletionSnapshot(t, ctx, db)
	ok, err := app.Mutation().DeleteAll(ctx, cmInput(f.cm), confirm)
	require.False(t, ok)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "SYNTHETIC_PRIVATE")
	after := deletionSnapshot(t, ctx, db)
	for table, hash := range before {
		if !strings.Contains(table, "audit") {
			require.Equal(t, hash, after[table], table)
		}
	}
	nrNoSuccess(t, ctx, db)
	enforcementExec(t, ctx, db, `DROP TRIGGER synthetic_cm_audit_failure ON user_cmnr_delete_audit_events`)
	ok, err = app.Mutation().DeleteAll(ctx, cmInput(f.cm), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE outcome='committed'`))
}

func cmRelatedWrites(t *testing.T, ctx context.Context, db *sql.DB, f deletionFixture) []nrWrite {
	t.Helper()
	writes := nrRelatedWrites(t, ctx, db, f)
	for i := range writes {
		if writes[i].name == "nr_delete" {
			writes[i].args = writes[i].args[:1]
		}
	}
	var msg uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id FROM outgoing_messages WHERE contact_method_id=$1`, f.cm).Scan(&msg))
	code := uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO user_verification_codes(id,contact_method_id,code,expires_at) VALUES($1,$2,123456,now()+'10 minutes'::interval)`, code, f.cm)
	var sub, subject int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO alert_status_subscriptions(contact_method_id,alert_id,last_alert_status) VALUES($1,$2,'triggered') RETURNING id`, f.cm, f.active).Scan(&sub))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id FROM auth_subjects WHERE cm_id=$1`, f.cm).Scan(&subject))
	var history int64
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id FROM message_status_history WHERE message_id=$1 LIMIT 1`, msg).Scan(&history))
	var signal int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO pending_signals(service_id,dest_id,message_id,params) VALUES($1,$2,$3,'{}') RETURNING id`, f.service, f.channel, msg).Scan(&signal))
	return append(writes,
		nrWrite{name: "new_owned_nr", query: `INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES($1,$2,19)`, args: []any{f.user, f.cm}},
		nrWrite{name: "verification_upsert", query: `INSERT INTO user_verification_codes(id,contact_method_id,code,expires_at) VALUES($1,$2,123456,now()+'10 minutes'::interval) ON CONFLICT(contact_method_id) DO UPDATE SET sent=false,expires_at=excluded.expires_at`, args: []any{uuid.New(), f.cm}},
		nrWrite{name: "root_disabled", query: `UPDATE user_contact_methods SET disabled=true WHERE id=$1`, args: []any{f.cm}},
		nrWrite{name: "root_pending", query: `UPDATE user_contact_methods SET pending=true WHERE id=$1`, args: []any{f.cm}},
		nrWrite{name: "owned_nr_delay", query: `UPDATE user_notification_rules SET delay_minutes=9 WHERE id=$1`, args: []any{f.nr}},
		nrWrite{name: "verification_update", query: `UPDATE user_verification_codes SET sent=true WHERE id=$1`, args: []any{code}},
		nrWrite{name: "verification_cleanup", query: `DELETE FROM user_verification_codes WHERE id=$1`, args: []any{code}},
		nrWrite{name: "verify_enable", query: `WITH v AS (DELETE FROM user_verification_codes WHERE id=$1 RETURNING contact_method_id) UPDATE user_contact_methods cm SET disabled=false FROM v WHERE cm.id=v.contact_method_id`, args: []any{code}},
		nrWrite{name: "subscription_update", query: `UPDATE alert_status_subscriptions SET last_alert_status='closed' WHERE id=$1`, args: []any{sub}},
		nrWrite{name: "new_subscription", query: `INSERT INTO alert_status_subscriptions(contact_method_id,alert_id,last_alert_status) VALUES($1,$2,'triggered')`, args: []any{f.cm, f.closed}},
		nrWrite{name: "message_update", query: `UPDATE outgoing_messages SET retry_count=retry_count+1 WHERE id=$1`, args: []any{msg}},
		nrWrite{name: "new_message", query: `INSERT INTO outgoing_messages(user_id,contact_method_id,message_type) VALUES($1,$2,'test_notification')`, args: []any{f.user, f.cm}},
		nrWrite{name: "auth_subject_update", query: `UPDATE auth_subjects SET provider_id='synthetic-changed' WHERE id=$1`, args: []any{subject}},
		nrWrite{name: "new_auth_subject", query: `INSERT INTO auth_subjects(user_id,cm_id,provider_id,subject_id) VALUES($1,$2,'synthetic',$3)`, args: []any{f.user, f.cm, uuid.NewString()}},
		nrWrite{name: "status_setting", query: `UPDATE users SET alert_status_log_contact_method_id=$2 WHERE id=$1`, args: []any{f.user, f.cm}},
		nrWrite{name: "message_history", query: `DELETE FROM message_status_history WHERE id=$1`, args: []any{history}},
		nrWrite{name: "new_history", query: `INSERT INTO message_status_history(message_id,status,status_details) VALUES($1,'pending','synthetic')`, args: []any{msg}},
		nrWrite{name: "pending_signal", query: `DELETE FROM pending_signals WHERE id=$1`, args: []any{signal}},
		nrWrite{name: "owner_scope", query: `UPDATE user_organization_assignments SET source_config_version='synthetic-changed' WHERE user_id=$1`, args: []any{f.user}},
		nrWrite{name: "service_scope", query: `UPDATE services SET name=name WHERE id=$1`, args: []any{f.service}},
		nrWrite{name: "schedule_scope", query: `UPDATE schedules SET name=name WHERE id=$1`, args: []any{f.schedule}},
		nrWrite{name: "policy_scope", query: `UPDATE escalation_policies SET name=name WHERE id=$1`, args: []any{f.policy}},
		nrWrite{name: "channel_scope", query: `UPDATE notification_channels SET name=name WHERE id=$1`, args: []any{f.channel}},
	)
}

func TestPostgresDeletionEnforcementCMDeleteFirst(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "CMProfileTest")
	for i := 0; i < 33; i++ {
		f := newDeletionFixture(t, ctx, db)
		w := cmRelatedWrites(t, ctx, db, f)[i]
		t.Run(w.name, func(t *testing.T) {
			version := cmVersion(t, ctx, db, f.cm)
			tx := nrBegin(t, ctx, db)
			carrier := cmEnforce(t, ctx, tx, f.cm, version)
			writer, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			t.Cleanup(func() { _ = writer.Rollback() })
			done := nrWaiter(t, ctx, db, writer, w.query, w.args...)
			result, err := contactmethod.NewStore(nil).DeleteForAuditTx(carrier, tx, f.cm.String())
			require.NoError(t, err)
			require.Len(t, result.Targets, 1)
			require.True(t, result.Targets[0].Deleted)
			require.NoError(t, tx.Commit())
			err = <-done
			if strings.HasPrefix(w.name, "new_") && w.name != "new_cm" && w.name != "new_nr" && w.name != "new_cycle" || w.name == "nr_parent" || w.name == "status_setting" || w.name == "verification_upsert" {
				require.Error(t, err)
				require.NoError(t, writer.Rollback())
			} else {
				require.NoError(t, err)
				require.NoError(t, writer.Commit())
			}
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, f.cm))
		})
	}
	nrNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementCMWriterFirst(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "CMProfileTest")
	for i := 0; i < 33; i++ {
		f := newDeletionFixture(t, ctx, db)
		w := cmRelatedWrites(t, ctx, db, f)[i]
		t.Run(w.name, func(t *testing.T) {
			version := cmVersion(t, ctx, db, f.cm)
			writer, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			t.Cleanup(func() { _ = writer.Rollback() })
			_, err = writer.ExecContext(ctx, w.query, w.args...)
			require.NoError(t, err)
			tx := nrBegin(t, ctx, db)
			_, err = collector.Enforce(ctx, tx, cmSelectors(f.cm), version, true, authorizeDeletionFixture(cmRoot(f.cm)))
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
			require.NoError(t, writer.Commit())
			fresh := cmVersion(t, ctx, db, f.cm)
			if fresh != version {
				tx = nrBegin(t, ctx, db)
				_, err = collector.Enforce(ctx, tx, cmSelectors(f.cm), version, true, authorizeDeletionFixture(cmRoot(f.cm)))
				enforceCode(t, err, ds.DeletionDependencyChanged)
				require.NoError(t, tx.Rollback())
			}
			tx = nrBegin(t, ctx, db)
			carrier := cmEnforce(t, ctx, tx, f.cm, fresh)
			result, err := contactmethod.NewStore(nil).DeleteForAuditTx(carrier, tx, f.cm.String())
			require.NoError(t, err)
			require.Len(t, result.Targets, 1)
			require.NoError(t, tx.Rollback())
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, f.cm))
		})
	}
	nrNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementCMStoreBypass(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "CMProfileTest")
	f := newDeletionFixture(t, ctx, db)
	app := enforcementApp(t, ctx, db)
	tx := nrBegin(t, ctx, db)
	require.Error(t, app.CMStore.Delete(ctx, tx, f.cm.String()))
	_, err := app.CMStore.DeleteForAuditTx(ctx, tx, f.cm.String())
	enforceCode(t, err, ds.DeletionUnavailable)
	nrCarrier := nrEnforce(t, ctx, tx, f.nr, nrVersion(t, ctx, db, f.nr))
	_, err = app.CMStore.DeleteForAuditTx(nrCarrier, tx, f.cm.String())
	enforceCode(t, err, ds.DeletionUnavailable)
	cmCarrier := cmEnforce(t, ctx, tx, f.cm, cmVersion(t, ctx, db, f.cm))
	_, err = app.NRStore.DeleteForAuditTx(cmCarrier, tx, f.nr.String())
	enforceCode(t, err, ds.DeletionUnavailable)
	require.Error(t, app.NRStore.DeleteTx(cmCarrier, tx, f.nr.String()))
	enforceCode(t, guard.RequireDelete(cmCarrier, tx, ds.ResourceUser, []string{f.user.String()}), ds.DeletionUnavailable)
	_, err = app.CMStore.DeleteForAuditTx(cmCarrier, tx, uuid.NewString())
	enforceCode(t, err, ds.DeletionUnavailable)
	result, err := app.CMStore.DeleteForAuditTx(cmCarrier, tx, f.cm.String())
	require.NoError(t, err)
	require.Len(t, result.CascadeRules, 1)
	require.True(t, result.CascadeRules[0].Deleted)
	_, err = app.CMStore.DeleteForAuditTx(cmCarrier, tx, f.cm.String())
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	nrNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementCMGuardLifecycle(t *testing.T) {
	nativeGuardLifecycle(t, ds.ResourceContactMethod)
}

func TestPostgresDeletionEnforcementCMIndependent(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "CMProfileTest")
	other := newDeletionFixture(t, ctx, db)
	writes := []nrWrite{
		{name: "other_owner_cm", query: `UPDATE user_contact_methods SET disabled=true WHERE id=$1`, args: []any{other.cm}},
		{name: "other_owner_nr", query: `UPDATE user_notification_rules SET delay_minutes=12 WHERE id=$1`, args: []any{other.nr}},
		{name: "other_org_service", query: `UPDATE services SET name=name WHERE id=$1`, args: []any{other.service}},
		{name: "rotation", query: `UPDATE rotations SET name=name WHERE id=$1`, args: []any{other.rotation}},
		{name: "key", query: `UPDATE integration_keys SET name=name WHERE id=$1`, args: []any{other.key}},
		{name: "alert", query: `UPDATE alerts SET summary=summary WHERE id=$1`, args: []any{other.active}},
	}
	for _, first := range []bool{true, false} {
		for _, w := range writes {
			t.Run(fmt.Sprint(first)+w.name, func(t *testing.T) {
				f := newDeletionFixture(t, ctx, db)
				version := cmVersion(t, ctx, db, f.cm)
				writer, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				t.Cleanup(func() { _ = writer.Rollback() })
				_, err = writer.ExecContext(ctx, `SET LOCAL lock_timeout='250ms'`)
				require.NoError(t, err)
				write := func() {
					res, err := writer.ExecContext(ctx, w.query, w.args...)
					require.NoError(t, err)
					n, err := res.RowsAffected()
					require.NoError(t, err)
					require.EqualValues(t, 1, n)
				}
				if first {
					write()
				}
				tx := nrBegin(t, ctx, db)
				carrier := cmEnforce(t, ctx, tx, f.cm, version)
				var global int
				require.NoError(t, tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation JOIN pg_namespace n ON n.oid=c.relnamespace WHERE l.pid=pg_backend_pid() AND n.nspname='public' AND l.mode IN ('ShareLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock')`).Scan(&global))
				require.Zero(t, global)
				if !first {
					write()
					require.NoError(t, writer.Commit())
				}
				result, err := contactmethod.NewStore(nil).DeleteForAuditTx(carrier, tx, f.cm.String())
				require.NoError(t, err)
				require.Len(t, result.Targets, 1)
				require.NoError(t, tx.Commit())
				if first {
					require.NoError(t, writer.Commit())
				}
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, f.cm))
			})
		}
	}
}

func TestPostgresDeletionEnforcementCMAuthorization(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(ctx, "CMProfileTest")
	app := enforcementApp(t, sys, db)
	for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN", "PLATFORM_ADMIN"} {
		t.Run(role, func(t *testing.T) {
			f := newDeletionFixture(t, ctx, db)
			actor := f.user
			enforcementExec(t, ctx, db, `UPDATE user_contact_methods SET private=true WHERE id=$1`, f.cm)
			if role == "ORG_ADMIN" {
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, actor)
			}
			if role == "PLATFORM_ADMIN" {
				actor = f.actor
				enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, actor)
			}
			human := previewAdmit(t, ctx, db, actor)
			confirm := enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeContactMethod, ID: f.cm.String()})
			for _, q := range []string{`UPDATE users SET name=name WHERE id=$1`, `UPDATE user_organization_assignments SET source_config_version=source_config_version WHERE user_id=$1`} {
				tx := nrBegin(t, human, db)
				carrier, err := collector.Enforce(human, tx, cmSelectors(f.cm), confirm.ExpectedImpactVersion, true, func(context.Context, *sql.Tx, collector.Target) error { return nil })
				require.NoError(t, err)
				writer, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				t.Cleanup(func() { _ = writer.Rollback() })
				done := nrWaiter(t, ctx, db, writer, q, actor)
				require.NoError(t, tx.Rollback())
				require.NoError(t, <-done)
				require.NoError(t, writer.Rollback())
				enforceCode(t, guard.RequireDelete(carrier, tx, ds.ResourceContactMethod, []string{f.cm.String()}), ds.DeletionUnavailable)
			}
			ok, err := app.Mutation().DeleteAll(human, cmInput(f.cm), confirm)
			require.NoError(t, err)
			require.True(t, ok)
			if role != "PLATFORM_ADMIN" {
				colleague := f
				colleague.user = f.actor
				cm, _ := nrSibling(t, ctx, db, colleague, 0)
				_, err = app.Mutation().DeleteAll(human, cmInput(cm), nil)
				require.Error(t, err)
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, cm))
			}
		})
	}
	for _, change := range []string{"role", "assignment"} {
		t.Run("stale_"+change, func(t *testing.T) {
			f := newDeletionFixture(t, ctx, db)
			human := previewAdmit(t, ctx, db, f.user)
			version := enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeContactMethod, ID: f.cm.String()}).ExpectedImpactVersion
			writer, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			t.Cleanup(func() { _ = writer.Rollback() })
			q := `UPDATE users SET role='admin' WHERE id=$1`
			if change == "assignment" {
				q = `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`
			}
			_, err = writer.ExecContext(ctx, q, f.user)
			require.NoError(t, err)
			tx := nrBegin(t, human, db)
			_, err = collector.Enforce(human, tx, cmSelectors(f.cm), version, true, func(context.Context, *sql.Tx, collector.Target) error { return nil })
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
			require.NoError(t, writer.Commit())
			_, err = app.Mutation().DeleteAll(human, cmInput(f.cm), &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: version, AcknowledgeImpacts: true})
			enforceCode(t, err, ds.DeletionUnavailable)
		})
	}
}

func TestPostgresDeletionEnforcementCMDiscoveryWindow(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "CMProfileTest")
	for _, change := range []string{"owner", "sibling_identity", "new_sibling", "verification", "subscription", "message", "auth_subject"} {
		t.Run(change, func(t *testing.T) {
			f := newDeletionFixture(t, ctx, db)
			other := newDeletionFixture(t, ctx, db)
			sibling, nr := nrSibling(t, ctx, db, f, 3)
			version := cmVersion(t, ctx, db, f.cm)
			config, err := pgx.ParseConfig(uri)
			require.NoError(t, err)
			needle := "SELECT id::text,user_id::text FROM public.user_contact_methods WHERE id=ANY"
			if change == "new_sibling" {
				needle = "SELECT id::text FROM public.users WHERE id=ANY"
			}
			barrier := &nrQueryBarrier{needle: needle, arrived: make(chan struct{}), resume: make(chan struct{})}
			config.Tracer = barrier
			traced := sql.OpenDB(stdlib.GetConnector(*config))
			defer traced.Close()
			tx := nrBegin(t, ctx, traced)
			done := make(chan error, 1)
			go func() {
				_, err := collector.Enforce(ctx, tx, cmSelectors(f.cm), version, true, authorizeDeletionFixture(cmRoot(f.cm)))
				done <- err
			}()
			select {
			case <-barrier.arrived:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			switch change {
			case "owner":
				enforcementExec(t, ctx, db, `UPDATE user_contact_methods SET user_id=$2 WHERE id=$1`, f.cm, other.user)
			case "sibling_identity":
				writer, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				t.Cleanup(func() { _ = writer.Rollback() })
				_, err = writer.ExecContext(ctx, `DELETE FROM user_notification_rules WHERE id=$1`, nr)
				require.NoError(t, err)
				_, err = writer.ExecContext(ctx, `INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES($1,$2,3)`, f.user, sibling)
				require.NoError(t, err)
				require.NoError(t, writer.Commit())
			case "new_sibling":
				cmInsert(t, ctx, db, uuid.New(), f.user)
			case "verification":
				enforcementExec(t, ctx, db, `INSERT INTO user_verification_codes(id,contact_method_id,code,expires_at) VALUES($1,$2,123456,now()+'10 minutes'::interval)`, uuid.New(), f.cm)
			case "subscription":
				enforcementExec(t, ctx, db, `INSERT INTO alert_status_subscriptions(contact_method_id,alert_id,last_alert_status) VALUES($1,$2,'triggered')`, f.cm, f.active)
			case "message":
				enforcementExec(t, ctx, db, `INSERT INTO outgoing_messages(user_id,contact_method_id,message_type) VALUES($1,$2,'test_notification')`, f.user, f.cm)
			case "auth_subject":
				enforcementExec(t, ctx, db, `INSERT INTO auth_subjects(user_id,cm_id,provider_id,subject_id) VALUES($1,$2,'synthetic',$3)`, f.user, f.cm, uuid.NewString())
			}
			close(barrier.resume)
			err = <-done
			if change == "owner" || change == "sibling_identity" || change == "new_sibling" {
				enforceCode(t, err, ds.DeletionUnavailable)
			} else {
				enforceCode(t, err, ds.DeletionDependencyChanged)
			}
			require.NoError(t, tx.Rollback())
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, f.cm))
		})
	}
	nrNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementCMClosureIntegrity(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "CMProfileTest")
	f := newDeletionFixture(t, ctx, db)
	otherCM, _ := nrSibling(t, ctx, db, f, 3)
	code := uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO user_verification_codes(id,contact_method_id,code,expires_at) VALUES($1,$2,123456,now()+'10 minutes'::interval)`, code, otherCM)
	enforcementExec(t, ctx, db, `UPDATE outgoing_messages SET user_verification_code_id=$2 WHERE contact_method_id=$1`, f.cm, code)
	// This real FK edge can exist in the schema, but lies outside the proved
	// CM-only verification closure. Do not pretend it is empty or cascade it.
	tx := nrBegin(t, ctx, db)
	_, err := collector.Enforce(ctx, tx, cmSelectors(f.cm), "", true, authorizeDeletionFixture(cmRoot(f.cm)))
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM outgoing_messages WHERE contact_method_id=$1 AND user_verification_code_id=$2`, f.cm, code))
	// A malformed incoming NR must not evade discovery by its owner column.
	other := newDeletionFixture(t, ctx, db)
	enforcementExec(t, ctx, db, `UPDATE user_contact_methods SET user_id=$2 WHERE id=$1`, other.cm, f.user)
	tx = nrBegin(t, ctx, db)
	_, err = collector.Enforce(ctx, tx, cmSelectors(other.cm), "", true, authorizeDeletionFixture(cmRoot(other.cm)))
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	nrNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementCMEmptyLegacyAndBudget(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "CMProfileTest")
	f := newDeletionFixture(t, ctx, db)
	empty := uuid.New()
	cmInsert(t, ctx, db, empty, f.actor)
	app := enforcementApp(t, ctx, db)
	// An empty CM with no owner cycles has no warning/cascade and needs no confirmation.
	ok, err := app.Mutation().DeleteAll(ctx, cmInput(empty), nil)
	require.NoError(t, err)
	require.True(t, ok)
	tx := nrBegin(t, ctx, db)
	carrier := cmEnforce(t, ctx, tx, f.cm, cmVersion(t, ctx, db, f.cm))
	require.NoError(t, app.CMStore.Delete(carrier, tx, f.cm.String()))
	require.NoError(t, tx.Commit())
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, f.nr))
	f = newDeletionFixture(t, ctx, db)
	enforcementExec(t, ctx, db, `INSERT INTO outgoing_messages(user_id,contact_method_id,message_type) SELECT $1,$2,'test_notification' FROM generate_series(1,10000)`, f.user, f.cm)
	tx = nrBegin(t, ctx, db)
	_, err = collector.Enforce(ctx, tx, cmSelectors(f.cm), "", true, authorizeDeletionFixture(cmRoot(f.cm)))
	enforceCode(t, err, ds.DeletionPreviewLimitExceeded)
	require.NoError(t, tx.Rollback())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, f.cm))
}

func TestPostgresDeletionEnforcementCMBundleBoundary(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "CMProfileTest")
	for _, kind := range []string{"root_bundle", "bundled_child", "incoming_non_fk"} {
		t.Run(kind, func(t *testing.T) {
			f := newDeletionFixture(t, ctx, db)
			app := enforcementApp(t, ctx, db)
			var msg uuid.UUID
			require.NoError(t, db.QueryRowContext(ctx, `SELECT id FROM outgoing_messages WHERE contact_method_id=$1`, f.cm).Scan(&msg))
			switch kind {
			case "root_bundle":
				enforcementExec(t, ctx, db, `UPDATE outgoing_messages SET message_type='alert_notification_bundle' WHERE id=$1`, msg)
			case "bundled_child":
				enforcementExec(t, ctx, db, `UPDATE outgoing_messages SET last_status='bundled',status_details=$2 WHERE id=$1`, msg, uuid.NewString())
			case "incoming_non_fk":
				other := newDeletionFixture(t, ctx, db)
				enforcementExec(t, ctx, db, `UPDATE outgoing_messages SET last_status='bundled',status_details=$2 WHERE contact_method_id=$1`, other.cm, msg.String())
			}
			previewRejected(t, previewHTTP(t, ctx, app, previewInput(graphql2.DeletionTargetTypeContactMethod, f.cm), 1, nil), string(ds.DeletionUnavailable))
			_, err := app.Mutation().DeleteAll(ctx, cmInput(f.cm), nil)
			enforceCode(t, err, ds.DeletionUnavailable)
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, f.cm))
			nrNoSuccess(t, ctx, db)
		})
	}
	// The existing writer protocol really conflicts in both directions, including
	// a new non-FK link to an ordinary selected message. No writer rewrite is used.
	f := newDeletionFixture(t, ctx, db)
	version := cmVersion(t, ctx, db, f.cm)
	writer, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = writer.Rollback() })
	_, err = writer.ExecContext(ctx, `LOCK outgoing_messages IN EXCLUSIVE MODE`)
	require.NoError(t, err)
	tx := nrBegin(t, ctx, db)
	_, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='150ms'`)
	require.NoError(t, err)
	_, err = collector.Enforce(ctx, tx, cmSelectors(f.cm), version, true, authorizeDeletionFixture(cmRoot(f.cm)))
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	require.NoError(t, writer.Rollback())
	tx = nrBegin(t, ctx, db)
	carrier := cmEnforce(t, ctx, tx, f.cm, version)
	writer, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = writer.Rollback() })
	done := nrWaiter(t, ctx, db, writer, `LOCK outgoing_messages IN EXCLUSIVE MODE`)
	result, err := contactmethod.NewStore(nil).DeleteForAuditTx(carrier, tx, f.cm.String())
	require.NoError(t, err)
	require.Len(t, result.Targets, 1)
	require.NoError(t, tx.Commit())
	require.NoError(t, <-done)
	require.NoError(t, writer.Commit())
	nrNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementCMMessageLogReference(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "CMProfileTest")
	f := newDeletionFixture(t, ctx, db)
	var alert, log int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO alerts(service_id,status,dedup_key,summary) VALUES($1,'active',gen_random_uuid()::text,'synthetic message-only alert') RETURNING id`, f.service).Scan(&alert))
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO alert_logs(alert_id,event,message) VALUES($1,'acknowledged','synthetic retained history') RETURNING id`, alert).Scan(&log))
	msg := uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO outgoing_messages(id,user_id,contact_method_id,message_type,alert_log_id,alert_id,last_status,sent_at) VALUES($1,$2,$3,'alert_status_update',$4,$5,'sent',now())`, msg, f.user, f.cm, log, alert)
	version := cmVersion(t, ctx, db, f.cm)
	for _, w := range []nrWrite{
		{name: "log_parent", query: `UPDATE alert_logs SET alert_id=$2 WHERE id=$1`, args: []any{log, f.closed}},
		{name: "message_only_alert", query: `UPDATE alerts SET summary=summary WHERE id=$1`, args: []any{alert}},
	} {
		t.Run(w.name, func(t *testing.T) {
			writer, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			t.Cleanup(func() { _ = writer.Rollback() })
			_, err = writer.ExecContext(ctx, w.query, w.args...)
			require.NoError(t, err)
			tx := nrBegin(t, ctx, db)
			_, err = collector.Enforce(ctx, tx, cmSelectors(f.cm), version, true, authorizeDeletionFixture(cmRoot(f.cm)))
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
			require.NoError(t, writer.Rollback())
			tx = nrBegin(t, ctx, db)
			cmEnforce(t, ctx, tx, f.cm, version)
			writer, err = db.BeginTx(ctx, nil)
			require.NoError(t, err)
			t.Cleanup(func() { _ = writer.Rollback() })
			done := nrWaiter(t, ctx, db, writer, w.query, w.args...)
			require.NoError(t, tx.Rollback())
			require.NoError(t, <-done)
			require.NoError(t, writer.Rollback())
		})
	}
	app := enforcementApp(t, ctx, db)
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeContactMethod, ID: f.cm.String()})
	ok, err := app.Mutation().DeleteAll(ctx, cmInput(f.cm), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM outgoing_messages WHERE id=$1`, msg))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM alert_logs WHERE id=$1 AND alert_id=$2`, log, alert))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM alerts WHERE id=$1 AND status='active'`, alert))
}
