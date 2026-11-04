package graphqlapp_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/config"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/schedule/rotation"
	"github.com/target/goalert/schedule/rule"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/util"
	"github.com/target/goalert/validation"
)

// Legacy nested UpdateSchedule is explicitly NOT COVERED by durable C5 audit.
// This test proves compatibility, rather than claiming that missing audit passes D09.
func TestD09C5LegacyPostgresCompatibility(t *testing.T) {
	if os.Getenv("MS_ONCALL_CORE_MIGRATION_TEST_POSTGRES_ENABLE") != "1" {
		t.Skip("explicit PostgreSQL test enable required")
	}
	h := harness.NewHarness(t, `INSERT INTO users(id,name,email,role) VALUES({{uuid "actor"}},'Synthetic actor','','user'); INSERT INTO schedules(id,organization_id,name,time_zone) VALUES({{uuid "schedule"}},{{smokeOrganizationID}},'Legacy Schedule','Etc/UTC');`, "")
	t.Cleanup(h.Close)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, h.App().Engine.Pause(ctx))
	db := h.App().DB()
	_, err := db.Exec(`UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, h.UUID("actor"))
	require.NoError(t, err)
	session := uuid.NewString()
	ctx = permission.UserSourceContext(ctx, h.UUID("actor"), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session})
	r, err := auth.NewRequester(h.UUID("actor"), session)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, r)
	c, err := executioncontext.NewHumanExecutionContextConstructor(organization.NewStore(db))
	require.NoError(t, err)
	ec, err := c.Construct(ctx)
	require.NoError(t, err)
	ctx = (config.Config{}).Context(executioncontext.WithExecutionContext(ctx, ec))
	ss, err := schedule.NewStore(ctx, db, nil)
	require.NoError(t, err)
	rs, err := rotation.NewStore(ctx, db)
	require.NoError(t, err)
	rules, err := rule.NewStore(ctx, db)
	require.NoError(t, err)
	a := graphqlapp.App{DB: db, ScheduleStore: ss, RotationStore: rs, RuleStore: rules}
	read := func() string {
		var v string
		require.NoError(t, db.QueryRow(`SELECT description FROM schedules WHERE id=$1`, h.UUID("schedule")).Scan(&v))
		return v
	}
	count := func(q string) int { var n int; require.NoError(t, db.QueryRow(q).Scan(&n)); return n }
	abort := errors.New("synthetic outer abort")
	for _, commit := range []bool{false, true} {
		name := "rollback"
		if commit {
			name = "commit"
		}
		t.Run(name, func(t *testing.T) {
			before := read()
			value := "Legacy " + name
			err := graphqlapp.WithContextTxForTest(ctx, db, func(inner context.Context, outer *sql.Tx) error {
				require.True(t, graphqlapp.HasInheritedContextTxForTest(inner))
				// A different/nil db argument still joins the original helper Tx.
				require.NoError(t, graphqlapp.WithContextTxForTest(inner, nil, func(same context.Context, tx *sql.Tx) error {
					require.Same(t, outer, tx)
					require.Equal(t, inner, same)
					return nil
				}))
				ok, err := a.Mutation().UpdateSchedule(inner, graphql2.UpdateScheduleInput{ID: h.UUID("schedule"), Description: &value})
				require.NoError(t, err)
				require.True(t, ok)
				var staged string
				require.NoError(t, outer.QueryRow(`SELECT description FROM schedules WHERE id=$1`, h.UUID("schedule")).Scan(&staged))
				require.Equal(t, value, staged)
				require.Equal(t, before, read())
				require.Zero(t, count(`SELECT count(*) FROM schedule_rotation_update_audit_events`), "NOT COVERED: no independently committed inner audit")
				if !commit {
					return abort
				}
				return nil
			})
			if commit {
				require.NoError(t, err)
				require.Equal(t, value, read())
			} else {
				require.ErrorIs(t, err, abort)
				require.Equal(t, before, read())
			}
		})
	}
	t.Run("handled-inner-error-does-not-poison", func(t *testing.T) {
		require.NoError(t, graphqlapp.WithContextTxForTest(ctx, db, func(inner context.Context, tx *sql.Tx) error {
			bad := ""
			_, err := a.Mutation().UpdateSchedule(inner, graphql2.UpdateScheduleInput{ID: h.UUID("schedule"), Name: &bad})
			require.Error(t, err)
			value := "After handled error"
			ok, err := a.Mutation().UpdateSchedule(inner, graphql2.UpdateScheduleInput{ID: h.UUID("schedule"), Description: &value})
			require.NoError(t, err)
			require.True(t, ok)
			return nil
		}))
		require.Equal(t, "After handled error", read())
	})
	t.Run("original-timezone-error-and-panic", func(t *testing.T) {
		before := read()
		err := graphqlapp.WithContextTxForTest(ctx, db, func(inner context.Context, tx *sql.Tx) error {
			bad := "SYNTHETIC_BAD_TIMEZONE"
			_, err := a.Mutation().UpdateSchedule(inner, graphql2.UpdateScheduleInput{ID: h.UUID("schedule"), TimeZone: &bad})
			_, original := util.LoadLocation(bad)
			require.EqualError(t, err, validation.NewFieldError("timeZone", original.Error()).Error(), "original nested validation message preserved")
			value := "Panic must roll back"
			_, err = a.Mutation().UpdateSchedule(inner, graphql2.UpdateScheduleInput{ID: h.UUID("schedule"), Description: &value})
			require.NoError(t, err)
			return abort
		})
		require.ErrorIs(t, err, abort)
		require.Equal(t, before, read())
		require.PanicsWithValue(t, "synthetic panic", func() {
			_ = graphqlapp.WithContextTxForTest(ctx, db, func(inner context.Context, tx *sql.Tx) error {
				value := "Panic staged"
				_, err := a.Mutation().UpdateSchedule(inner, graphql2.UpdateScheduleInput{ID: h.UUID("schedule"), Description: &value})
				require.NoError(t, err)
				panic("synthetic panic")
			})
		})
		require.Equal(t, before, read())
	})
	t.Run("legacy-request-cancellation", func(t *testing.T) {
		before := read()
		request, stop := context.WithCancel(ctx)
		defer stop()
		err := graphqlapp.WithContextTxForTest(request, db, func(inner context.Context, tx *sql.Tx) error {
			value := "Cancelled legacy write"
			ok, err := a.Mutation().UpdateSchedule(inner, graphql2.UpdateScheduleInput{ID: h.UUID("schedule"), Description: &value})
			require.NoError(t, err)
			require.True(t, ok)
			stop()
			return nil
		})
		require.Error(t, err)
		// Wait only for test cleanup. The legacy helper itself retains its
		// original cancellation behavior and promises no release barrier.
		require.Eventually(t, func() bool {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return false
			}
			_, err = tx.Exec(`SELECT id FROM schedules WHERE id=$1 FOR UPDATE NOWAIT`, h.UUID("schedule"))
			_ = tx.Rollback()
			return err == nil
		}, 5*time.Second, time.Millisecond)
		require.Equal(t, before, read())
	})
	// A real existing production chain: CreateSchedule -> CreateRotation ->
	// UpdateScheduleTarget. It must remain one legacy transaction, without C5.
	for _, commit := range []bool{false, true} {
		name := "Parent Rollback"
		if commit {
			name = "Parent Commit"
		}
		t.Run(name, func(t *testing.T) {
			err := graphqlapp.WithContextTxForTest(ctx, db, func(inner context.Context, tx *sql.Tx) error {
				s, err := a.Mutation().CreateSchedule(inner, graphql2.CreateScheduleInput{Name: name, TimeZone: "Etc/UTC", Targets: []graphql2.ScheduleTargetInput{{NewRotation: &graphql2.CreateRotationInput{Name: name + " Rotation", TimeZone: "Etc/UTC", Type: rotation.TypeDaily, Start: time.Now()}, Rules: []graphql2.ScheduleRuleInput{{}}}}})
				require.NoError(t, err)
				require.NotEmpty(t, s.ID)
				var n int
				require.NoError(t, tx.QueryRow(`SELECT count(*) FROM schedules WHERE name=$1`, name).Scan(&n))
				require.Equal(t, 1, n)
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM schedules WHERE name=$1`, name).Scan(&n))
				require.Zero(t, n, "child must not create an independent business commit")
				if !commit {
					return abort
				}
				return nil
			})
			if commit {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, abort)
			}
			for _, table := range []string{"schedules", "rotations"} {
				var n int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM `+table+` WHERE name=$1`, map[string]string{"schedules": name, "rotations": name + " Rotation"}[table]).Scan(&n))
				if commit {
					require.Equal(t, 1, n)
				} else {
					require.Zero(t, n)
				}
			}
		})
	}
	before := read()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	s, err := ss.FindOneForUpdate(ctx, tx, h.UUID("schedule"), nil)
	require.NoError(t, err)
	s.Description = "Direct caller-owned Store"
	require.NoError(t, ss.UpdateTx(ctx, tx, s, nil))
	require.Equal(t, before, read())
	require.NoError(t, tx.Rollback())
	require.Equal(t, before, read())
	require.Zero(t, count(`SELECT count(*) FROM schedule_rotation_update_audit_events`), "NOT COVERED: legacy and direct Store never produce durable C5 events")
	type untrustedKey string
	var fakeKey untrustedKey = "txKey"
	require.False(t, graphqlapp.HasInheritedContextTxForTest(context.WithValue(ctx, fakeKey, tx)))
	require.False(t, graphqlapp.HasInheritedContextTxForTest(nil))
	if dir := os.Getenv("SCHEDULE_UPDATE_AUDIT_EVIDENCE"); dir != "" {
		var dbName string
		require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&dbName))
		b, err := json.MarshalIndent(map[string]any{"database": dbName, "legacy_audit_coverage": "NOT COVERED", "events": count(`SELECT count(*) FROM schedule_rotation_update_audit_events`), "production_parent_chain": "CreateSchedule -> CreateRotation -> UpdateScheduleTarget", "commit_rollback_handled_error_panic": "PASS"}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "legacy-postgres.json"), append(b, '\n'), 0600))
	}
}
