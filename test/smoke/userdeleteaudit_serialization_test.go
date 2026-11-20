package smoke

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/executioncontext"
	overridestore "github.com/target/goalert/override"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func TestUserDeleteAuditCoveredSerialization(t *testing.T) {
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	db := h.App().DB()
	var name string
	require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&name))
	for _, mode := range []string{"user_user", "user_user_reverse", "user_cmnr", "cmnr_user", "user_override", "override_user"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			u, v := smokeOwnedUser(t, h), smokeOwnedUser(t, h)
			cm, nr := sd8CMNR(t, h, u)
			s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
			o := uuid.NewString()
			sd8Exec(t, h, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,remove_user_id,start_time,end_time) VALUES($1,$2,$3,$4,'2020-01-01','2020-01-02')`, o, s, u, v)
			user := []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}}
			otherUser := []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: v}}
			mixed := []assignment.RawTarget{{Type: assignment.TargetTypeContactMethod, ID: cm}, {Type: assignment.TargetTypeNotificationRule, ID: nr}}
			before := smokeUserBusinessState(t, h)
			successes := smokeDeletionSuccesses(t, h)
			ok, err := sd7App(h).Mutation().DeleteAll(sd3System(), mixed, nil)
			require.Error(t, err)
			require.False(t, ok)
			require.Equal(t, before, smokeUserBusinessState(t, h))
			require.Equal(t, successes, smokeDeletionSuccesses(t, h))
			// The original Mixed-root input remains a negative control. CM-only
			// owns and actually cascades its NR in the legal serialization path.
			cn := []assignment.RawTarget{{Type: assignment.TargetTypeContactMethod, ID: cm}}
			override := []assignment.RawTarget{{Type: assignment.TargetTypeUserOverride, ID: o}}
			first, second := user, otherUser
			switch mode {
			case "user_user_reverse":
				first, second = otherUser, user
			case "user_cmnr":
				second = cn
			case "cmnr_user":
				first, second = cn, user
			case "user_override":
				second = override
			case "override_user":
				first, second = override, user
			}
			c1, err := sd8PGConnector(harness.DBURL(name))
			require.NoError(t, err)
			c2, err := sd8PGConnector(harness.DBURL(name))
			require.NoError(t, err)
			d1, d2 := sql.OpenDB(c1), sql.OpenDB(c2)
			defer d1.Close()
			defer d2.Close()
			a1, a2 := sd7App(h), sd7App(h)
			a1.DB, a2.DB = d1, d2
			a1.OverrideStore, err = overridestore.NewStore(ctx, d1)
			require.NoError(t, err)
			a2.OverrideStore, err = overridestore.NewStore(ctx, d2)
			require.NoError(t, err)
			ctx1, ctx2 := permission.SystemContext(ctx, "Engine"), permission.SystemContext(ctx, "Engine")
			if mode == "override_user" {
				ctx1 = sd8Human(t, h, ctx)
			}
			if mode == "user_override" {
				ctx2 = sd8Human(t, h, ctx)
			}
			entered := make(chan int, 1)
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			c1.afterEntry = func(ctx context.Context, c driver.Conn) error {
				pid, err := sd8NativePID(ctx, c)
				if err != nil {
					return err
				}
				entered <- pid
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			result1, result2 := make(chan error, 1), make(chan error, 1)
			finished1, finished2 := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(finished1)
				_, err := smokeDeleteAll(t, h, a1, ctx1, first)
				result1 <- err
			}()
			var pid1 int
			select {
			case pid1 = <-entered:
			case <-ctx.Done():
				t.Fatal("first entry not reached")
			}
			go func() {
				defer close(finished2)
				_, err := smokeDeleteAll(t, h, a2, ctx2, second)
				result2 <- err
			}()
			defer func() {
				unblock()
				select {
				case <-finished1:
				case <-ctx.Done():
				}
				select {
				case <-finished2:
				case <-ctx.Done():
				}
			}()
			var pid2 int
			require.Eventually(t, func() bool {
				return db.QueryRowContext(ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE 'SELECT pg_advisory_xact_lock(1297305411%' LIMIT 1`, pid1).Scan(&pid2) == nil
			}, 5*time.Second, 10*time.Millisecond)
			sd8WaitLock(t, db, pid2, pid1)
			var businessLocks int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM pg_locks WHERE pid=$1 AND granted AND relation=ANY(ARRAY['users'::regclass,'user_contact_methods'::regclass,'user_notification_rules'::regclass,'user_overrides'::regclass,'rotation_participants'::regclass,'rotation_state'::regclass])`, pid2).Scan(&businessLocks))
			require.Zero(t, businessLocks)
			unblock()
			require.NoError(t, <-result1)
			secondErr := <-result2
			if mode == "user_override" {
				require.NoError(t, secondErr, "existing missing Override no-op does not create a success witness")
			} else {
				smokeDeletionCode(t, secondErr, ds.DeletionDependencyChanged)
			}
			wantUser := int64(0)
			if mode == "user_user" || mode == "user_cmnr" || mode == "user_override" {
				wantUser = 1
			}
			require.Equal(t, wantUser, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u))
			require.Equal(t, int64(1)-wantUser, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
			if mode == "user_user" || mode == "user_user_reverse" {
				firstUser := u
				if mode == "user_user_reverse" {
					firstUser = v
				}
				require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects f JOIN user_delete_audit_events e USING(event_id) WHERE f.resource_type='user_override' AND f.resource_key=$1 AND e.root_id=$2`, o, firstUser))
				wantV := int64(0)
				if mode == "user_user_reverse" {
					wantV = 1
				}
				require.Equal(t, wantV, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, v))
				require.Equal(t, int64(1)-wantV, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, v))
			}
			if mode == "user_cmnr" {
				require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE root_id IN ($1,$2) AND record_kind='success_witness'`, cm, nr))
				require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE resource_key IN ($1,$2)`, cm, nr))
			}
			if mode == "cmnr_user" {
				require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness' AND schema_version=1`, cm))
				require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, nr))
				require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_cmnr_delete_audit_events a CROSS JOIN LATERAL jsonb_array_elements(a.effects) f WHERE a.root_id=$1 AND a.record_kind='success_witness' AND f->>'resource_uuid'=$2 AND f->>'resource_type'='notification_rule' AND f->>'provenance'='IMPLICIT_FK_CASCADE'`, cm, nr))
				require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE resource_key IN ($1,$2)`, cm, nr))
			}
			if mode == "override_user" {
				require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_override_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, o))
				require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE resource_key=$1`, o))
			}
			t.Logf("covered mode=%s first_pid=%d second_pid=%d second_business_locks_before_entry=%d; one actual first transaction, no automatic retry of changed Preview", mode, pid1, pid2, businessLocks)
		})
	}
}

func TestUserDeleteAuditExternalRotationWriter(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	var name string
	require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&name))
	for _, mode := range []string{"participant", "state"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			u, v := smokeOwnedUser(t, h), smokeOwnedUser(t, h)
			rot := sd6Root(t, h, "rotation", harness.SmokeOrganizationID)
			for i, user := range []string{u, v} {
				sd8Exec(t, h, `INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES($1,$2,$3,$4)`, uuid.New(), rot, user, i)
			}
			original := []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}}
			smokeAssertBlockedUser(t, h, sd7App(h), original)
			preserved := smokeUserBusinessState(t, h)
			// This root is independent; the referenced original User/Rotation
			// survive unchanged throughout the successful table-fence scenario.
			target := smokeOwnedUser(t, h)
			connector, err := sd8PGConnector(harness.DBURL(name))
			require.NoError(t, err)
			controlled := sql.OpenDB(connector)
			defer controlled.Close()
			app := sd7App(h)
			app.DB = controlled
			entered := make(chan int, 1)
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			connector.beforeDelete = func(ctx context.Context, c driver.Conn) error {
				pid, err := sd8NativePID(ctx, c)
				if err != nil {
					return err
				}
				entered <- pid
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			done := make(chan error, 1)
			go func() {
				_, err := smokeDeleteAll(t, h, app, permission.SystemContext(ctx, "Engine"), []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: target}})
				done <- err
			}()
			var pid int
			select {
			case pid = <-entered:
			case <-ctx.Done():
				t.Fatal("no capture barrier")
			}
			writer, err := db.Conn(ctx)
			require.NoError(t, err)
			defer writer.Close()
			var wpid int
			require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&wpid))
			added := uuid.NewString()
			stateBefore := sd8Scalar(t, h, `SELECT version FROM rotation_state WHERE rotation_id=$1`, rot)
			writeDone := make(chan error, 1)
			go func() {
				var err error
				if mode == "participant" {
					_, err = writer.ExecContext(ctx, `INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES($1,$2,$3,0)`, added, rot, v)
				} else {
					_, err = writer.ExecContext(ctx, `UPDATE rotation_state SET version=version+1 WHERE rotation_id=$1`, rot)
				}
				writeDone <- err
			}()
			sd8WaitLock(t, db, wpid, pid)
			unblock()
			require.NoError(t, <-done)
			require.NoError(t, <-writeDone)
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, target))
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
			if mode == "participant" {
				require.EqualValues(t, 3, sd8Scalar(t, h, `SELECT count(*) FROM rotation_participants WHERE rotation_id=$1`, rot))
				require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM rotation_participants WHERE id=$1 AND user_id=$2`, added, v))
			} else {
				require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(*) FROM rotation_participants WHERE rotation_id=$1`, rot))
				require.Equal(t, stateBefore+1, sd8Scalar(t, h, `SELECT version FROM rotation_state WHERE rotation_id=$1`, rot))
			}
			require.NotEmpty(t, preserved["rotation_participants"])
			t.Logf("external %s writer actually executed after waiting; original referenced User and Rotation retained", mode)
		})
	}
}

func sd8Human(t *testing.T, h *harness.Harness, parent context.Context) context.Context {
	t.Helper()
	user, session := h.UUID("user-a"), uuid.NewString()
	ctx := permission.UserSourceContext(h.Config().Context(parent), user, permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session})
	requester, err := auth.NewRequester(user, session)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, requester)
	constructor, err := executioncontext.NewHumanExecutionContextConstructor(h.App().OrganizationStore)
	require.NoError(t, err)
	ec, err := constructor.Construct(ctx)
	require.NoError(t, err)
	return executioncontext.WithExecutionContext(ctx, ec)
}
