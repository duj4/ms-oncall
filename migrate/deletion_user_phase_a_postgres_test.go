package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/user"
	audit "github.com/target/goalert/user/deleteaudit"
)

// Phase A characterizations are investigation evidence, not a User profile.
// In particular they never manufacture a carrier or bypass the deletion guard.
type userPhaseAFixture struct {
	org, user uuid.UUID
	users     *user.Store
	schedules *schedule.Store
}

func newUserPhaseAFixture(t *testing.T, ctx context.Context, db *sql.DB) userPhaseAFixture {
	t.Helper()
	orgs := organization.NewStore(db)
	org, err := orgs.CreateNormal(ctx, organization.CreateNormalOrganizationInput{
		DisplayName: "User Phase A", CanonicalName: "user-phase-a-" + uuid.NewString(),
		CorporateMappingKey: uuid.NewString(), TimeZone: "Asia/Shanghai",
	})
	require.NoError(t, err)
	users, err := user.NewStore(ctx, db)
	require.NoError(t, err)
	u, err := users.Insert(ctx, &user.User{Name: "User Phase A", Role: permission.RoleUser})
	require.NoError(t, err)
	id := uuid.MustParse(u.ID)
	_, err = orgs.CreateUserOrganizationAssignment(ctx, organization.CreateUserOrganizationAssignmentInput{
		UserID: id, UserOrganizationAssignmentValues: organization.UserOrganizationAssignmentValues{
			EffectiveOrganizationID: org.ID, EffectiveOrganizationClassification: organization.ClassificationNormal,
			Role: organization.OrganizationRoleMember, MappingOutcome: organization.MappingOutcomeExactlyOne,
			Evaluation: organization.AssignmentEvaluation{AuthoritativeEvaluatedAt: time.Now(), SourceConfigVersion: "user-phase-a", MatchedCount: 1},
		},
	})
	require.NoError(t, err)
	schedules, err := schedule.NewStore(ctx, db, users)
	require.NoError(t, err)
	return userPhaseAFixture{org: org.ID, user: id, users: users, schedules: schedules}
}

func (f userPhaseAFixture) newSchedule(t *testing.T, ctx context.Context) uuid.UUID {
	t.Helper()
	s, err := f.schedules.Create(ctx, &schedule.Schedule{OrganizationID: f.org, Name: "schedule-" + uuid.NewString(), TimeZone: time.UTC})
	require.NoError(t, err)
	return uuid.MustParse(s.ID)
}

func userPhaseATemp(id uuid.UUID) schedule.TemporarySchedule {
	start := time.Now().UTC().Truncate(time.Minute).Add(time.Hour)
	return schedule.TemporarySchedule{Start: start, End: start.Add(time.Hour), Shifts: []schedule.FixedShift{{Start: start, End: start.Add(time.Hour), UserID: id.String()}}}
}

func userPhaseATx(t *testing.T, ctx context.Context, db *sql.DB) *sql.Tx {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	_, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='1s'`)
	require.NoError(t, err)
	return tx
}

func TestPostgresDeletionUserPhaseASessionIdentityContract(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserPhaseA")
	f := newUserPhaseAFixture(t, ctx, db)
	handler, err := auth.NewHandler(ctx, db, auth.HandlerConfig{UserStore: f.users})
	require.NoError(t, err)
	token, err := handler.CreateSession(ctx, "synthetic-user-phase-a", f.user.String())
	require.NoError(t, err)
	var safe uuid.UUID
	var rawProjection, safeProjection []byte
	var key string
	var hasSafeField, rawValid, renamedSafeValid bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT audit_resource_id,
 jsonb_build_object('id',id,'user_id',user_id,'row_version',xmin::text::bigint),
 jsonb_build_object('audit_resource_id',audit_resource_id,'user_id',user_id,'row_version',xmin::text::bigint),
 user_delete_projection('user_session')->>'key',
 (user_delete_projection('user_session')->'fields') ? 'audit_resource_id'
 FROM auth_user_sessions WHERE id=$1`, token.ID).Scan(&safe, &rawProjection, &safeProjection, &key, &hasSafeField))
	// Credentials remain synthetic and in memory; assertion failures must not
	// print either identity or the projection containing the credential.
	require.True(t, safe != uuid.Nil && safe != token.ID)
	require.Equal(t, "id", key)
	require.False(t, hasSafeField)
	require.NoError(t, audit.ValidateSnapshot("user_session", token.ID.String(), rawProjection))
	require.Error(t, audit.ValidateSnapshot("user_session", safe.String(), safeProjection))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT user_delete_snapshot_valid($1::jsonb,'user_session'),user_delete_snapshot_valid($2::jsonb,'user_session')`, string(rawProjection), string(safeProjection)).Scan(&rawValid, &renamedSafeValid))
	require.True(t, rawValid)
	require.False(t, renamedSafeValid)
	root := ds.Resource{Kind: ds.ResourceUser, ID: f.user.String()}
	facts, err := collectDeletion(t, ctx, db, root, collector.Limits{})
	require.NoError(t, err)
	require.Equal(t, ds.DependenciesComplete, facts.Collection.Completeness)
	var found bool
	for _, d := range facts.Collection.Dependencies {
		if d.Relationship == ds.RelationshipUserIdentity && d.Referencing.Kind == ds.ResourceUserSession {
			found = d.Referencing.ID == safe.String()
			require.True(t, d.Referencing.ID != token.ID.String())
		}
	}
	require.True(t, found, "Preview uses the SD9 safe identity; SD8 capture still selects the physical id")
	t.Log("CONFIRMED: SD8 physical session-id projection and SD9 safe Preview identity differ; no User deletion or audit write attempted")
}

func TestPostgresDeletionUserPhaseAFailClosed(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserPhaseA")
	f := newUserPhaseAFixture(t, ctx, db)
	app := enforcementApp(t, ctx, db)
	for _, ids := range [][]uuid.UUID{{f.user}, {f.user, f.user, uuid.New()}, {uuid.New()}, {uuid.Nil}} {
		var raw []assignment.RawTarget
		for _, id := range ids {
			raw = append(raw, assignment.RawTarget{Type: assignment.TargetTypeUser, ID: id.String()})
		}
		_, err := app.Mutation().DeleteAll(ctx, raw, nil)
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	for _, audited := range []bool{false, true} {
		tx := userPhaseATx(t, ctx, db)
		var err error
		if audited {
			_, err = f.users.DeleteManyForAuditTx(ctx, tx, []string{f.user.String()}, audit.Event{}, nil)
		} else {
			err = f.users.DeleteManyTx(ctx, tx, []string{f.user.String()})
		}
		enforceCode(t, err, ds.DeletionUnavailable)
		require.NoError(t, tx.Rollback())
	}
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_organization_assignments WHERE user_id=$1`, f.user))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events WHERE outcome='committed'`))
}

func TestPostgresDeletionUserPhaseAJSONUserLockGap(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserPhaseA")
	f := newUserPhaseAFixture(t, ctx, db)
	for _, first := range []string{"user_lock_first", "writer_first"} {
		t.Run(first, func(t *testing.T) {
			id := f.newSchedule(t, ctx)
			rootTx, writer := userPhaseATx(t, ctx, db), userPhaseATx(t, ctx, db)
			lock := func() {
				var present bool
				require.NoError(t, rootTx.QueryRowContext(ctx, `SELECT true FROM users WHERE id=$1 FOR UPDATE NOWAIT`, f.user).Scan(&present))
				require.True(t, present)
			}
			write := func() {
				require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, writer, id, userPhaseATemp(f.user), &f.org))
			}
			if first == "user_lock_first" {
				lock()
				write()
			} else {
				write()
				lock()
			}
			// Both transactions are still open. No sleep or scheduling inference:
			// completion of the real Store write and NOWAIT lock is the barrier.
			var unblocked bool
			require.NoError(t, writer.QueryRowContext(ctx, `SELECT cardinality(pg_blocking_pids(pg_backend_pid()))=0`).Scan(&unblocked))
			require.True(t, unblocked)
			require.NoError(t, writer.Commit())
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_data WHERE schedule_id=$1 AND data->'V1'->'TemporarySchedules'->0->'Shifts'->0->>'UserID'=$2`, id, f.user.String()))
			require.NoError(t, rootTx.Rollback())
		})
	}
	t.Log("CONFIRMED GAP: both lock orders allow a real JSON reference write while the User UPDATE lock is held; root was retained, not deleted")
}

func TestPostgresDeletionUserPhaseAJSONOldReadGap(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserPhaseA")
	f := newUserPhaseAFixture(t, ctx, db)
	id := f.newSchedule(t, ctx)
	conf, err := pgx.ParseConfig(uri)
	require.NoError(t, err)
	barrier := &nrQueryBarrier{needle: "-- name: SchedUpdateData", arrived: make(chan struct{}), resume: make(chan struct{})}
	conf.Tracer = barrier
	traced := sql.OpenDB(stdlib.GetConnector(*conf))
	defer traced.Close()
	store, err := schedule.NewStore(ctx, traced, f.users)
	require.NoError(t, err)
	done := make(chan error, 1)
	defer func() { // release the Writer before closing its pool on any failure
		select {
		case <-barrier.resume:
		default:
			close(barrier.resume)
		}
	}()
	go func() { done <- store.SetTemporaryScheduleScoped(ctx, nil, id, userPhaseATemp(f.user), &f.org) }()
	select {
	case <-barrier.arrived:
	case err := <-done:
		require.NoError(t, err)
		t.Fatal("Writer did not reach its post-validation SQL barrier")
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	rootTx := userPhaseATx(t, ctx, db)
	var present bool
	require.NoError(t, rootTx.QueryRowContext(ctx, `SELECT true FROM users WHERE id=$1 FOR UPDATE NOWAIT`, f.user).Scan(&present))
	require.True(t, present)
	close(barrier.resume)
	require.NoError(t, <-done)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_data WHERE schedule_id=$1`, id))
	require.NoError(t, rootTx.Rollback())
	t.Log("CONFIRMED GAP: Writer validated the User, then committed JSON after a concurrent User UPDATE lock; no unsafe delete executed")
}

func TestPostgresDeletionUserPhaseANormalJSONShape(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserPhaseA")
	f := newUserPhaseAFixture(t, ctx, db)
	id := f.newSchedule(t, ctx)
	require.NoError(t, f.schedules.SetOnCallNotificationRulesScoped(ctx, nil, id, []schedule.OnCallNotificationRule{}, &f.org))
	var normalNull bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT data->'V1'->'TemporarySchedules'='null'::jsonb FROM schedule_data WHERE schedule_id=$1`, id).Scan(&normalNull))
	require.True(t, normalNull)
	root := ds.Resource{Kind: ds.ResourceUser, ID: f.user.String()}
	facts, err := collectDeletion(t, ctx, db, root, collector.Limits{})
	if err == nil {
		require.NotEqual(t, ds.DependenciesComplete, facts.Collection.Completeness)
	} else {
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	t.Log("CONFIRMED LIMIT: a normal Store emits a null TemporarySchedules slice; the existing global User JSON collector fails closed")
}

func TestPostgresDeletionUserPhaseACatalog(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	rows, err := db.QueryContext(ctx, `SELECT c.conrelid::regclass::text,a.attname,format_type(a.atttypid,a.atttypmod),c.confdeltype::text,c.condeferrable,c.condeferred
 FROM pg_constraint c JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=ANY(c.conkey)
 WHERE c.contype='f' AND c.confrelid='public.users'::regclass ORDER BY 1,2`)
	require.NoError(t, err)
	defer rows.Close()
	count := 0
	for rows.Next() {
		var table, column, typ, action string
		var deferrable, deferred bool
		require.NoError(t, rows.Scan(&table, &column, &typ, &action, &deferrable, &deferred))
		require.Equal(t, "uuid", typ)
		require.False(t, deferrable)
		require.False(t, deferred)
		t.Logf("User FK: %s.%s %s ON DELETE=%s DEFERRABLE=%t DEFERRED=%t", table, column, typ, action, deferrable, deferred)
		count++
	}
	require.NoError(t, rows.Err())
	require.Equal(t, 22, count, "inventory changed; re-open Phase A")
	require.NoError(t, rows.Close())
	var outbound, deferred bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT c.condeferrable,c.condeferred FROM pg_constraint c JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=ANY(c.conkey) WHERE c.contype='f' AND c.conrelid='public.users'::regclass AND a.attname='alert_status_log_contact_method_id' AND c.confrelid='public.user_contact_methods'::regclass AND c.confdeltype='n'`).Scan(&outbound, &deferred))
	require.True(t, outbound)
	require.False(t, deferred)
	identities, err := db.QueryContext(ctx, `SELECT c.conrelid::regclass::text,c.contype::text,a.attname,format_type(a.atttypid,a.atttypmod)
 FROM pg_constraint c JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=ANY(c.conkey)
 WHERE c.contype IN ('p','u') AND c.conrelid=ANY(ARRAY['public.users'::regclass,'public.auth_subjects'::regclass,'public.auth_basic_users'::regclass,'public.auth_user_sessions'::regclass,'public.user_favorites'::regclass,'public.schedule_data'::regclass]) ORDER BY 1,2,3`)
	require.NoError(t, err)
	defer identities.Close()
	for identities.Next() {
		var table, constraint, column, typ string
		require.NoError(t, identities.Scan(&table, &constraint, &column, &typ))
		t.Logf("Identity: %s %s %s %s", table, constraint, column, typ)
	}
	require.NoError(t, identities.Err())
	require.NoError(t, identities.Close())
	// Only schema metadata is read. No existing credentials or user data leave
	// the disposable database; no migration/trigger/FK is disabled or changed.
	var triggers []byte
	require.NoError(t, db.QueryRowContext(ctx, `SELECT coalesce(jsonb_agg(tgname ORDER BY tgname),'[]') FROM pg_trigger WHERE tgrelid='public.users'::regclass AND NOT tgisinternal`).Scan(&triggers))
	var names []string
	require.NoError(t, json.Unmarshal(triggers, &names))
	require.Equal(t, []string{"trg_enforce_status_update_same_user"}, names)
}
