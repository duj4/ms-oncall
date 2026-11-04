package graphqlapp_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
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
	"github.com/target/goalert/schedule/rotation"
	"github.com/target/goalert/test/smoke/harness"
)

func TestD09C6LegacyPostgresCompatibility(t *testing.T) {
	if os.Getenv("MS_ONCALL_CORE_MIGRATION_TEST_POSTGRES_ENABLE") != "1" {
		t.Skip("explicit PostgreSQL test enable required")
	}
	h := harness.NewHarness(t, `INSERT INTO users(id,name,email,role) VALUES({{uuid "actor"}},'Synthetic actor','','user'),({{uuid "other"}},'Synthetic participant','','user');
 INSERT INTO rotations(id,organization_id,name,type,time_zone) VALUES({{uuid "rotation"}},{{smokeOrganizationID}},'Legacy Rotation','daily','Etc/UTC');
 INSERT INTO rotation_participants(id,rotation_id,user_id) VALUES({{uuid "part"}},{{uuid "rotation"}},{{uuid "actor"}});`, "")
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
	store, err := rotation.NewStore(ctx, db)
	require.NoError(t, err)
	a := graphqlapp.App{DB: db, RotationStore: store}
	read := func() string {
		var v string
		require.NoError(t, db.QueryRow(`SELECT description FROM rotations WHERE id=$1`, h.UUID("rotation")).Scan(&v))
		return v
	}
	count := func() int {
		var n int
		require.NoError(t, db.QueryRow(`SELECT count(*) FROM schedule_rotation_update_audit_events`).Scan(&n))
		return n
	}
	abort := errors.New("synthetic outer abort")
	for _, commit := range []bool{false, true} {
		name := "rollback"
		if commit {
			name = "commit"
		}
		t.Run(name, func(t *testing.T) {
			before := read()
			desc := "Legacy " + name
			rotName := "Legacy " + name
			start := h.Now()
			typ := rotation.TypeHourly
			shift := 2
			zone := "Etc/UTC"
			active := 1
			err := graphqlapp.WithContextTxForTest(ctx, db, func(inner context.Context, tx *sql.Tx) error {
				require.True(t, graphqlapp.HasInheritedContextTxForTest(inner))
				ok, err := a.Mutation().UpdateRotation(inner, graphql2.UpdateRotationInput{ID: h.UUID("rotation"), Name: &rotName, Description: &desc, Start: &start, Type: &typ, ShiftLength: &shift, TimeZone: &zone, UserIDs: []string{h.UUID("actor"), h.UUID("other")}, ActiveUserIndex: &active})
				require.NoError(t, err)
				require.True(t, ok)
				var staged string
				require.NoError(t, tx.QueryRow(`SELECT description FROM rotations WHERE id=$1`, h.UUID("rotation")).Scan(&staged))
				require.Equal(t, desc, staged)
				require.Equal(t, before, read())
				require.Zero(t, count(), "NOT COVERED: inherited inner cannot independently commit an audit")
				if !commit {
					return abort
				}
				return nil
			})
			if commit {
				require.NoError(t, err)
				require.Equal(t, desc, read())
			} else {
				require.ErrorIs(t, err, abort)
				require.Equal(t, before, read())
			}
			require.Zero(t, count())
		})
	}
	require.NoError(t, graphqlapp.WithContextTxForTest(ctx, db, func(inner context.Context, tx *sql.Tx) error {
		bad := ""
		_, err := a.Mutation().UpdateRotation(inner, graphql2.UpdateRotationInput{ID: h.UUID("rotation"), Name: &bad})
		require.Error(t, err)
		value := "After handled legacy validation"
		ok, err := a.Mutation().UpdateRotation(inner, graphql2.UpdateRotationInput{ID: h.UUID("rotation"), Description: &value})
		require.NoError(t, err)
		require.True(t, ok)
		return nil
	}))
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	rot, err := store.FindRotationForUpdateTx(ctx, tx, h.UUID("rotation"), nil)
	require.NoError(t, err)
	rot.Description = "Direct Store staged"
	require.NoError(t, store.UpdateRotationTx(ctx, tx, rot, nil))
	require.NoError(t, tx.Rollback())
	require.Zero(t, count(), "NOT COVERED: direct Store owns no durable C6 events")
}
