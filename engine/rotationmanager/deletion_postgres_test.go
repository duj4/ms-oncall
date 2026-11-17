package rotationmanager

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/migrate"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule/rotation"
)

type deletionStateBarrier struct {
	once            sync.Once
	arrived, resume chan struct{}
	pid             chan uint32
	pause           bool
}

func (b *deletionStateBarrier) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "UPDATE\n    rotation_state\nSET") {
		b.once.Do(func() { b.pid <- c.PgConn().PID() })
		return context.WithValue(ctx, deletionStateTraceKey{}, true)
	}
	return ctx
}

type deletionStateTraceKey struct{}

func (b *deletionStateBarrier) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	if b.pause && d.Err == nil && ctx.Value(deletionStateTraceKey{}) == true {
		close(b.arrived)
		select {
		case <-b.resume:
		case <-ctx.Done():
		}
	}
}

// The real engine worker runs, including its processing lock, scheduled River
// job, state calculation, RotMgrUpdate, and commit. No trigger is suppressed.
func TestPostgresDeletionEnforcementRotationManager(t *testing.T) {
	if os.Getenv("MS_ONCALL_CORE_MIGRATION_TEST_POSTGRES_ENABLE") != "1" {
		t.Skip("opt-in private PostgreSQL campaign")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ctx = permission.SystemContext(ctx, "RotationDeletionManagerTest")
	base := os.Getenv("DB_URL")
	require.NotEmpty(t, base)
	admin, err := pgx.Connect(ctx, base)
	require.NoError(t, err)
	defer admin.Close(ctx)
	name := "rotation_profile_manager_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	require.NoError(t, err)
	defer func() {
		_, err := admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize())
		require.NoError(t, err)
	}()
	parsed, err := url.Parse(base)
	require.NoError(t, err)
	parsed.Path = "/" + name
	uri := parsed.String()
	n, err := migrate.Up(ctx, uri, "")
	require.NoError(t, err)
	require.Equal(t, 306, n)
	db, err := sql.Open("pgx", uri)
	require.NoError(t, err)
	defer db.Close()
	for _, first := range []string{"engine", "delete"} {
		t.Run(first, func(t *testing.T) {
			org, user := uuid.New(), uuid.New()
			for _, q := range []struct {
				s string
				a []any
			}{
				{`INSERT INTO organizations(id,canonical_name,display_name,classification) VALUES($1,($1::uuid)::text,'synthetic','NORMAL')`, []any{org}},
				{`INSERT INTO normal_organizations(organization_id,corporate_mapping_key,iana_time_zone) VALUES($1,($1::uuid)::text,'UTC')`, []any{org}},
				{`INSERT INTO users(id,name) VALUES($1,'synthetic')`, []any{user}},
			} {
				_, err := db.ExecContext(ctx, q.s, q.a...)
				require.NoError(t, err)
			}
			_, err := organization.NewStore(db).CreateUserOrganizationAssignment(ctx, organization.CreateUserOrganizationAssignmentInput{UserID: user, UserOrganizationAssignmentValues: organization.UserOrganizationAssignmentValues{
				EffectiveOrganizationID: org, EffectiveOrganizationClassification: organization.ClassificationNormal, Role: organization.OrganizationRoleMember, MappingOutcome: organization.MappingOutcomeExactlyOne,
				Evaluation: organization.AssignmentEvaluation{AuthoritativeEvaluatedAt: time.Now(), SourceConfigVersion: "synthetic-rotation", MatchedCount: 1}}})
			require.NoError(t, err)
			store, err := rotation.NewStore(ctx, db)
			require.NoError(t, err)
			root, err := store.CreateRotationTx(ctx, nil, &rotation.Rotation{OrganizationID: org, Name: "rotation-" + uuid.NewString(), Type: rotation.TypeDaily, Start: time.Now().UTC().Add(-72 * time.Hour), ShiftLength: 1})
			require.NoError(t, err)
			id := uuid.MustParse(root.ID)
			require.NoError(t, store.AddRotationUsersTx(ctx, nil, root.ID, []string{user.String(), user.String()}))
			_, err = db.ExecContext(ctx, `UPDATE rotation_state SET shift_start=now()-interval '48 hours' WHERE rotation_id=$1`, id)
			require.NoError(t, err)
			barrier := &deletionStateBarrier{arrived: make(chan struct{}), resume: make(chan struct{}), pid: make(chan uint32, 1), pause: first == "engine"}
			conf, err := pgx.ParseConfig(uri)
			require.NoError(t, err)
			conf.Tracer = barrier
			traced := sql.OpenDB(stdlib.GetConnector(*conf))
			defer traced.Close()
			riverClient, err := river.NewClient(riverdatabasesql.New(traced), &river.Config{PollOnly: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
			require.NoError(t, err)
			manager, err := NewDB(ctx, traced, riverClient)
			require.NoError(t, err)
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			raw := []collector.Selector{{Kind: ds.ResourceRotation, ID: root.ID}}
			if first == "delete" {
				checked, _, err := guard.StabilizeRotation(ctx, tx, raw)
				require.NoError(t, err)
				facts, err := collector.Collect(checked, tx, ds.Resource{Kind: ds.ResourceRotation, ID: root.ID}, collector.Recheck, collector.Limits{}, func(context.Context, *sql.Tx, collector.Target) error { return nil })
				require.Error(t, err)
				require.Equal(t, ds.DependenciesUnsupported, facts.Collection.Completeness)
			}
			done := make(chan error, 1)
			go func() { done <- manager.updateRotation(ctx, &river.Job[UpdateArgs]{Args: UpdateArgs{RotationID: id}}) }()
			if first == "engine" {
				select {
				case <-barrier.arrived:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				_, err := collector.Enforce(ctx, tx, raw, "", false, func(context.Context, *sql.Tx, collector.Target) error { return nil })
				var safe *ds.DeletionSafetyError
				require.ErrorAs(t, err, &safe)
				require.Equal(t, ds.DeletionUnavailable, safe.Code)
				require.NoError(t, tx.Rollback())
				close(barrier.resume)
			} else {
				var pid uint32
				select {
				case pid = <-barrier.pid:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				for {
					var blocked bool
					require.NoError(t, db.QueryRowContext(ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&blocked))
					if blocked {
						break
					}
					require.NoError(t, ctx.Err())
				}
				require.NoError(t, tx.Rollback())
			}
			require.NoError(t, <-done)
			var roots, parts, states int
			require.NoError(t, db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM rotations WHERE id=$1),(SELECT count(*) FROM rotation_participants WHERE rotation_id=$1),(SELECT count(*) FROM rotation_state WHERE rotation_id=$1 AND shift_start>now()-interval '1 minute')`, id).Scan(&roots, &parts, &states))
			require.Equal(t, 1, roots)
			require.Equal(t, 2, parts)
			require.Equal(t, 1, states)
		})
	}
}
