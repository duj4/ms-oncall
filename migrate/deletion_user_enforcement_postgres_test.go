package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/config"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/graphql2"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/notification/nfydest"
	"github.com/target/goalert/notification/webhook"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/user"
	"github.com/target/goalert/user/contactmethod"
	useraudit "github.com/target/goalert/user/deleteaudit"
	"github.com/target/goalert/user/notificationrule"
)

func userProfileInput(ids ...uuid.UUID) []assignment.RawTarget {
	var out []assignment.RawTarget
	for _, id := range ids {
		out = append(out, assignment.RawTarget{Type: assignment.TargetTypeUser, ID: id.String()})
	}
	return out
}
func userProfilePreview(ids ...uuid.UUID) []graphql2.DeletionResourceInput {
	var out []graphql2.DeletionResourceInput
	for _, id := range ids {
		out = append(out, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeUser, ID: id.String()})
	}
	return out
}
func userProfileSelectors(ids ...uuid.UUID) []collector.Selector {
	var out []collector.Selector
	for _, id := range ids {
		out = append(out, collector.Selector{Kind: ds.ResourceUser, ID: id.String()})
	}
	return out
}
func userProfileRoot(id uuid.UUID) ds.Resource {
	return ds.Resource{Kind: ds.ResourceUser, ID: id.String()}
}
func userProfileVersion(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	facts, err := collectDeletion(t, ctx, db, userProfileRoot(id), collector.Limits{})
	require.NoError(t, err)
	return deletionPlan(t, userProfileRoot(id), facts).ImpactVersion()
}
func userProfileEnforce(t *testing.T, ctx context.Context, tx *sql.Tx, id uuid.UUID, version string) context.Context {
	t.Helper()
	bound, err := collector.Enforce(ctx, tx, userProfileSelectors(id), version, true, authorizeDeletionFixture(userProfileRoot(id)))
	require.NoError(t, err)
	return bound
}

type userNativeFixture struct {
	userPhaseAFixture
	cms, nrs    []uuid.UUID
	sessionSafe uuid.UUID
}

// All success roots, assignments, CMs, NRs and Sessions use production Stores.
// A configured webhook destination is only validated; no provider is called.
func userNativeLifecycle(t *testing.T, ctx context.Context, db *sql.DB, cmCount, nrCount int, session bool) userNativeFixture {
	t.Helper()
	f := userNativeFixture{userPhaseAFixture: newUserPhaseAFixture(t, ctx, db)}
	var cfg config.Config
	cfg.Webhook.Enable = true
	ctx = cfg.Context(ctx)
	registry := nfydest.NewRegistry()
	registry.RegisterProvider(ctx, webhook.NewSender(ctx, http.DefaultClient))
	cms := contactmethod.NewStore(registry)
	nrs, err := notificationrule.NewStore(ctx, db)
	require.NoError(t, err)
	for i := 0; i < cmCount; i++ {
		cm, err := cms.Create(ctx, db, &contactmethod.ContactMethod{Name: fmt.Sprintf("User owned %d", i), UserID: f.user.String(), Dest: webhook.NewWebhookDest("https://synthetic.test.invalid/" + uuid.NewString())})
		require.NoError(t, err)
		f.cms = append(f.cms, cm.ID)
		for j := 0; j < nrCount; j++ {
			nr, err := nrs.Insert(ctx, &notificationrule.NotificationRule{UserID: f.user.String(), ContactMethodID: cm.ID, DelayMinutes: j})
			require.NoError(t, err)
			f.nrs = append(f.nrs, uuid.MustParse(nr.ID))
		}
	}
	if session {
		handler, err := auth.NewHandler(ctx, db, auth.HandlerConfig{UserStore: f.users})
		require.NoError(t, err)
		token, err := handler.CreateSession(ctx, "synthetic-user-native", f.user.String())
		require.NoError(t, err)
		require.NoError(t, db.QueryRowContext(ctx, `SELECT audit_resource_id FROM auth_user_sessions WHERE id=$1`, token.ID).Scan(&f.sessionSafe))
		require.True(t, f.sessionSafe != uuid.Nil && f.sessionSafe != token.ID)
	}
	return f
}

func TestPostgresDeletionEnforcementUserBusiness(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserNative")
	app := enforcementApp(t, ctx, db)
	other := userNativeLifecycle(t, ctx, db, 1, 1, true)
	for _, shape := range []struct {
		cm, nr  int
		session bool
	}{{0, 0, false}, {1, 0, false}, {1, 1, false}, {3, 2, false}, {0, 0, true}, {1, 1, true}} {
		t.Run(fmt.Sprintf("cm%d-nr%d-session%v", shape.cm, shape.nr, shape.session), func(t *testing.T) {
			f := userNativeLifecycle(t, ctx, db, shape.cm, shape.nr, shape.session)
			confirm := enforcementPreview(t, ctx, app, userProfilePreview(f.user)...)
			if shape.session {
				_, err := app.Mutation().DeleteAll(ctx, userProfileInput(f.user), nil)
				enforceCode(t, err, ds.DeletionConfirmationRequired)
			}
			ok, err := app.Mutation().DeleteAll(ctx, userProfileInput(f.user, f.user, uuid.New(), uuid.Nil), confirm)
			require.NoError(t, err)
			require.True(t, ok)
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
			for _, table := range []string{"user_contact_methods", "user_notification_rules", "auth_user_sessions", "user_organization_assignments"} {
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+table+` WHERE user_id=$1`, f.user))
			}
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND outcome='committed' AND operation='user.delete' AND provenance='EXPLICIT' AND deletion_mechanism='explicit_sql'`, f.user))
			for typ, count := range map[string]int{"contact_method": len(f.cms), "notification_rule": len(f.nrs), "user_organization_assignment": 1, "user_session": 0} {
				if typ == "user_session" && shape.session {
					count = 1
				}
				require.Equal(t, count, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_effects f JOIN user_delete_audit_events e USING(event_id) WHERE e.root_id=$1 AND f.resource_type=$2 AND payload->>'deletion_mechanism'='fk_cascade'`, f.user, typ))
			}
			if shape.session {
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_effects f JOIN user_delete_audit_events e USING(event_id) WHERE e.root_id=$1 AND resource_type='user_session' AND resource_key=$2 AND payload#>>'{before,version}'='2' AND payload#>>'{before,audit_resource_id}'=$2 AND NOT((payload->'before') ? 'id')`, f.user, f.sessionSafe.String()))
			}
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, other.user))
			_, err = app.Mutation().DeleteAll(ctx, userProfileInput(f.user), nil)
			require.NoError(t, err)
			_, err = app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
			enforceCode(t, err, ds.DeletionDependencyChanged)
		})
	}
	f, g := userNativeLifecycle(t, ctx, db, 1, 1, true), userNativeLifecycle(t, ctx, db, 1, 1, true)
	confirm := enforcementPreview(t, ctx, app, userProfilePreview(f.user, g.user)...)
	_, err := app.Mutation().DeleteAll(ctx, userProfileInput(f.user, g.user), confirm)
	require.NoError(t, err)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM (SELECT request_id,execution_id,attempt_id FROM user_delete_audit_events WHERE root_id IN ($1,$2) AND outcome='committed' GROUP BY 1,2,3 HAVING count(*)=2) x`, f.user, g.user))
}

func TestPostgresDeletionEnforcementUserAuditFailure(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserNative")
	app := enforcementApp(t, ctx, db)
	f := userNativeLifecycle(t, ctx, db, 2, 2, true)
	other := userNativeLifecycle(t, ctx, db, 1, 1, true)
	parents := userNativeParentRows(t, ctx, db, f)
	userNativeAddReference(t, ctx, db, f, parents, "ended_json")
	beforeJSON := jsonWriterData(t, ctx, db, parents.schedule)
	require.NoError(t, f.users.AddAuthSubjectTx(ctx, nil, &user.AuthSubject{ProviderID: "synthetic", SubjectID: uuid.NewString(), UserID: f.user.String()}))
	enforcementExec(t, ctx, db, `INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time,end_time) VALUES($1,$2,now()-'2h'::interval,now()-'1h'::interval)`, parents.schedule, f.user)
	confirm := enforcementPreview(t, ctx, app, userProfilePreview(f.user)...)
	enforcementExec(t, ctx, db, `CREATE SEQUENCE user_failure_seen; CREATE FUNCTION user_native_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome='committed' THEN IF EXISTS(SELECT FROM users WHERE id=NEW.root_id) OR EXISTS(SELECT FROM user_contact_methods WHERE user_id=NEW.root_id) OR EXISTS(SELECT FROM user_notification_rules WHERE user_id=NEW.root_id) OR EXISTS(SELECT FROM auth_user_sessions WHERE user_id=NEW.root_id) THEN RAISE EXCEPTION 'delete not reached'; END IF; PERFORM nextval('user_failure_seen'); RAISE EXCEPTION 'synthetic append failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER user_native_failure BEFORE INSERT ON user_delete_audit_events FOR EACH ROW EXECUTE FUNCTION user_native_failure()`)
	_, err := app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
	require.Error(t, err)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT last_value FROM user_failure_seen WHERE is_called`))
	for table, count := range map[string]int{"users": 1, "user_contact_methods": 2, "user_notification_rules": 4, "auth_user_sessions": 1, "user_organization_assignments": 1, "auth_subjects": 1, "schedule_on_call_users": 1} {
		col := "user_id"
		if table == "users" {
			col = "id"
		}
		require.Equal(t, count, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+table+` WHERE `+col+`=$1`, f.user))
	}
	require.Equal(t, beforeJSON, jsonWriterData(t, ctx, db, parents.schedule))
	for _, table := range []string{"user_contact_methods", "user_notification_rules", "auth_user_sessions"} {
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+table+` WHERE user_id=$1`, other.user))
	}
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events WHERE outcome='committed'`))
	enforcementExec(t, ctx, db, `DROP TRIGGER user_native_failure ON user_delete_audit_events`)
	confirm = enforcementPreview(t, ctx, app, userProfilePreview(f.user)...)
	_, err = app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
	require.NoError(t, err)
	require.Equal(t, beforeJSON, jsonWriterData(t, ctx, db, parents.schedule))
}

func TestPostgresDeletionEnforcementUserGuard(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserNative")
	f := userNativeLifecycle(t, ctx, db, 1, 1, true)
	app := enforcementApp(t, ctx, db)
	version := userProfileVersion(t, ctx, db, f.user)
	for _, mode := range []string{"uncertified", "rollback_locked", "rollback_certified", "consume_rollback", "generation", "other_tx", "other_root", "wrong_selector"} {
		t.Run(mode, func(t *testing.T) {
			tx := userPhaseATx(t, ctx, db)
			_, err := tx.ExecContext(ctx, `SAVEPOINT before_locks`)
			require.NoError(t, err)
			bound := ctx
			if mode != "uncertified" {
				bound = userProfileEnforce(t, ctx, tx, f.user, version)
			}
			switch mode {
			case "rollback_locked", "rollback_certified":
				_, err = tx.ExecContext(ctx, `ROLLBACK TO before_locks`)
				require.NoError(t, err)
			case "consume_rollback":
				_, err = tx.ExecContext(ctx, `SAVEPOINT before_consume`)
				require.NoError(t, err)
				_, err = guard.ConsumeUser(bound, tx, []string{f.user.String()})
				require.NoError(t, err)
				_, err = tx.ExecContext(ctx, `ROLLBACK TO before_consume`)
				require.NoError(t, err)
			case "generation":
				_, err = tx.ExecContext(ctx, `SAVEPOINT before_new_generation`)
				require.NoError(t, err)
				_ = userProfileEnforce(t, ctx, tx, f.user, version)
				_, err = tx.ExecContext(ctx, `ROLLBACK TO before_new_generation`)
				require.NoError(t, err)
			case "other_tx":
				other := userPhaseATx(t, ctx, db)
				_, err = guard.ConsumeUser(bound, other, []string{f.user.String()})
				enforceCode(t, err, ds.DeletionUnavailable)
				require.NoError(t, other.Rollback())
				require.NoError(t, tx.Rollback())
				return
			case "other_root":
				_, err = guard.ConsumeCM(bound, tx, []string{f.cms[0].String()})
				enforceCode(t, err, ds.DeletionUnavailable)
				require.NoError(t, tx.Rollback())
				return
			case "wrong_selector":
				_, err = guard.ConsumeUser(bound, tx, []string{uuid.NewString()})
				enforceCode(t, err, ds.DeletionUnavailable)
				require.NoError(t, tx.Rollback())
				return
			}
			_, err = guard.ConsumeUser(bound, tx, []string{f.user.String()})
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
		})
	}
	missing := uuid.New()
	tx := userPhaseATx(t, ctx, db)
	bound, err := collector.Enforce(ctx, tx, userProfileSelectors(f.user, missing), version, true, authorizeDeletionFixture(userProfileRoot(f.user)))
	require.NoError(t, err)
	// Same UUID late insertion is deliberately committed AFTER certification.
	enforcementExec(t, ctx, db, `INSERT INTO users(id,name) VALUES($1,'late missing identity')`, missing)
	effective, err := guard.UserTargets(bound, tx, []string{missing.String(), f.user.String()})
	require.NoError(t, err)
	require.Equal(t, []string{f.user.String()}, effective)
	effective, err = guard.ConsumeUser(bound, tx, []string{missing.String(), f.user.String()})
	require.NoError(t, err)
	require.Equal(t, []string{f.user.String()}, effective)
	require.NoError(t, tx.Rollback())
	_, err = app.Mutation().DeleteAll(ctx, userProfileInput(uuid.Nil, uuid.New()), nil)
	require.NoError(t, err)
	_, err = app.Mutation().DeleteAll(ctx, userProfileInput(slicesRepeatService(f.user, 51)...), nil)
	require.Error(t, err)
	_, err = app.Mutation().DeleteAll(ctx, append(userProfileInput(f.user), cmInput(f.cms[0])...), nil)
	enforceCode(t, err, ds.DeletionUnavailable)
}

func TestPostgresDeletionEnforcementUserMissingStoresAndController(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserNative")
	f := userNativeLifecycle(t, ctx, db, 1, 1, true)
	for _, audited := range []bool{false, true} {
		writer := epProfileWriter(t, ctx, db)
		u, err := f.users.InsertTx(ctx, writer, &user.User{Name: "Late Store User", Role: permission.RoleUser})
		require.NoError(t, err)
		id := uuid.MustParse(u.ID)
		tx := userPhaseATx(t, ctx, db)
		bound, err := collector.Enforce(ctx, tx, userProfileSelectors(id, uuid.Nil), "", false, authorizeDeletionFixture(userProfileRoot(id)))
		require.NoError(t, err)
		require.NoError(t, writer.Commit())
		if audited {
			result, err := f.users.DeleteManyForAuditTx(bound, tx, []string{id.String(), uuid.Nil.String()}, useraudit.Event{}, nil)
			require.NoError(t, err)
			require.Empty(t, result.Receipts)
			require.Empty(t, result.Targets)
		} else {
			require.NoError(t, f.users.DeleteManyTx(bound, tx, []string{id.String(), uuid.Nil.String()}))
		}
		require.NoError(t, tx.Commit())
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, id))
	}
	writer := epProfileWriter(t, ctx, db)
	u, err := f.users.InsertTx(ctx, writer, &user.User{Name: "Late Controller User", Role: permission.RoleUser})
	require.NoError(t, err)
	id := uuid.MustParse(u.ID)
	traced, b := overrideProfileTraced(t, uri, "VALUES($1,'certified'")
	app := enforcementApp(t, ctx, traced)
	done := make(chan error, 1)
	go func() { _, err := app.Mutation().DeleteAll(ctx, userProfileInput(id, uuid.Nil), nil); done <- err }()
	select {
	case <-b.arrived:
	case err := <-done:
		require.NoError(t, err)
		t.Fatal("no certification")
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.NoError(t, writer.Commit())
	close(b.resume)
	require.NoError(t, <-done)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, id))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events WHERE outcome='committed'`))
	// A locked checkpoint alone grants no Store deletion capability.
	tx := userPhaseATx(t, ctx, db)
	checked, _, err := guard.StabilizeUser(ctx, tx, userProfileSelectors(f.user))
	require.NoError(t, err)
	require.True(t, guard.StableUser(checked, tx, userProfileRoot(f.user)))
	_, err = guard.ConsumeUser(checked, tx, []string{f.user.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	// A real NR certificate cannot be used for its User owner.
	tx = userPhaseATx(t, ctx, db)
	nrCtx, err := collector.Enforce(ctx, tx, nrSelectors(f.nrs[0]), nrVersion(t, ctx, db, f.nrs[0]), true, authorizeDeletionFixture(nrRoot(f.nrs[0])))
	require.NoError(t, err)
	_, err = guard.ConsumeUser(nrCtx, tx, []string{f.user.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
}
