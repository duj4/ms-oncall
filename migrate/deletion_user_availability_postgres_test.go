package migrate

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/permission"
)

func TestPostgresDeletionEnforcementUserIndependentWriters(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserNative")
	f, g := userNativeLifecycle(t, ctx, db, 1, 1, true), userNativeLifecycle(t, ctx, db, 1, 1, true)
	p := userNativeParentRows(t, ctx, db, g)
	service, key := uuid.New(), uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO services(id,organization_id,name,escalation_policy_id) VALUES($1,$2,($1::uuid)::text,$3)`, service, g.org, p.policy)
	enforcementExec(t, ctx, db, `INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,'native independent','generic')`, key, service)
	version := userProfileVersion(t, ctx, db, f.user)
	for _, first := range []string{"writer", "delete"} {
		for _, kind := range []string{"service", "key", "schedule", "rotation", "policy", "cm", "nr", "other_user", "override", "participant"} {
			t.Run(first+"/"+kind, func(t *testing.T) {
				var query string
				var args []any
				switch kind {
				case "service":
					query = `UPDATE services SET description=description WHERE id=$1`
					args = []any{service}
				case "key":
					query = `UPDATE integration_keys SET name=name WHERE id=$1`
					args = []any{key}
				case "schedule":
					query = `UPDATE schedules SET description=description WHERE id=$1`
					args = []any{p.schedule}
				case "rotation":
					query = `UPDATE rotations SET description=description WHERE id=$1`
					args = []any{p.rotation}
				case "policy":
					query = `UPDATE escalation_policies SET description=description WHERE id=$1`
					args = []any{p.policy}
				case "cm":
					query = `UPDATE user_contact_methods SET name=name WHERE id=$1`
					args = []any{g.cms[0]}
				case "nr":
					query = `UPDATE user_notification_rules SET delay_minutes=delay_minutes WHERE id=$1`
					args = []any{g.nrs[0]}
				case "other_user":
					query = `UPDATE users SET name=name WHERE id=$1`
					args = []any{g.user}
				case "override":
					query = `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($1,$2,$3,now()+'1h'::interval,now()+'2h'::interval)`
					args = []any{uuid.New(), p.schedule, g.user}
				case "participant":
					query = `INSERT INTO rotation_participants(rotation_id,user_id,position) VALUES($1,$2,0)`
					args = []any{p.rotation, g.user}
				}
				tx, writer := userPhaseATx(t, ctx, db), epProfileWriter(t, ctx, db)
				contended := kind == "override" || kind == "participant"
				if first == "writer" {
					result, err := writer.ExecContext(ctx, query, args...)
					require.NoError(t, err)
					n, err := result.RowsAffected()
					require.NoError(t, err)
					require.EqualValues(t, 1, n)
					_, err = collector.Enforce(ctx, tx, userProfileSelectors(f.user), version, true, authorizeDeletionFixture(userProfileRoot(f.user)))
					if contended {
						require.Error(t, err)
					} else {
						require.NoError(t, err)
					}
					require.NoError(t, tx.Rollback())
					require.NoError(t, writer.Rollback())
					return
				}
				_ = userProfileEnforce(t, ctx, tx, f.user, version)
				if contended {
					var pid int
					require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
					done := make(chan error, 1)
					go func() { _, err := writer.ExecContext(ctx, query, args...); done <- err }()
					overrideWait(t, ctx, db, pid, done)
					require.NoError(t, tx.Rollback())
					require.NoError(t, <-done)
				} else {
					result, err := writer.ExecContext(ctx, query, args...)
					require.NoError(t, err)
					n, err := result.RowsAffected()
					require.NoError(t, err)
					require.EqualValues(t, 1, n)
					require.NoError(t, tx.Rollback())
				}
				require.NoError(t, writer.Rollback())
			})
		}
	}
}
