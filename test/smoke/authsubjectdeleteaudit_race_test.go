package smoke

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/user"
)

func TestAuthSubjectDeleteRealSerialization(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	var name string
	require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&name))
	for _, mode := range []string{"a_a", "a_rollback_a", "a_user", "user_a", "a_cm", "cm_a", "user_rollback_a", "cm_rollback_a", "cross_owner_cm_a"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 18*time.Second)
			defer cancel()
			ctx = permission.SystemContext(ctx, "Engine")
			owner := sd7User(t, h)
			cmOwner := owner
			if mode == "cross_owner_cm_a" {
				cmOwner = sd7User(t, h)
			}
			cm, _ := sd8CMNR(t, h, cmOwner)
			id, subject := asSubject(t, h, owner, cm)
			input := user.AuthSubject{UserID: owner, ProviderID: "SYNTHETIC_AUTH_PROVIDER", SubjectID: subject}
			c1, err := sd8PGConnector(harness.DBURL(name))
			require.NoError(t, err)
			c2, err := sd8PGConnector(harness.DBURL(name))
			require.NoError(t, err)
			d1, d2 := sql.OpenDB(c1), sql.OpenDB(c2)
			defer d1.Close()
			defer d2.Close()
			a1, a2 := sd7App(h), sd7App(h)
			a1.DB, a2.DB = d1, d2
			a1.UserStore, err = user.NewStore(ctx, d1)
			require.NoError(t, err)
			a2.UserStore, err = user.NewStore(ctx, d2)
			require.NoError(t, err)
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
			rollback := strings.Contains(mode, "rollback")
			if rollback {
				var injected atomic.Bool
				c1.beforeCommit = func(ctx context.Context, c driver.Conn) error {
					if injected.CompareAndSwap(false, true) {
						_, _ = c.(driver.ExecerContext).ExecContext(ctx, `SELECT 1/0`, nil)
					}
					return nil
				}
			}
			parent := func(which string) []assignment.RawTarget {
				if which == "user" {
					return []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: owner}}
				}
				return []assignment.RawTarget{{Type: assignment.TargetTypeContactMethod, ID: cm}}
			}
			first, second := make(chan error, 1), make(chan error, 1)
			go func() {
				var err error
				switch {
				case strings.HasPrefix(mode, "user_"):
					_, err = a1.Mutation().DeleteAll(ctx, parent("user"))
				case strings.HasPrefix(mode, "cm_") || mode == "cross_owner_cm_a":
					_, err = a1.Mutation().DeleteAll(ctx, parent("cm"))
				default:
					_, err = a1.Mutation().DeleteAuthSubject(ctx, input)
				}
				first <- err
			}()
			var pid1 int
			select {
			case pid1 = <-entered:
			case <-ctx.Done():
				t.Fatal("first advisory barrier not reached")
			}
			go func() {
				var err error
				switch mode {
				case "a_user":
					_, err = a2.Mutation().DeleteAll(ctx, parent("user"))
				case "a_cm":
					_, err = a2.Mutation().DeleteAll(ctx, parent("cm"))
				default:
					_, err = a2.Mutation().DeleteAuthSubject(ctx, input)
				}
				second <- err
			}()
			var pid2 int
			require.Eventually(t, func() bool {
				return db.QueryRowContext(ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE 'SELECT pg_advisory_xact_lock(1297305411%' LIMIT 1`, pid1).Scan(&pid2) == nil
			}, 4*time.Second, 10*time.Millisecond)
			var businessLocks int
			require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks WHERE pid=$1 AND granted AND relation=ANY(ARRAY['auth_subjects'::regclass,'users'::regclass,'user_contact_methods'::regclass,'user_organization_assignments'::regclass])`, pid2).Scan(&businessLocks))
			require.Zero(t, businessLocks)
			unblock()
			err = <-first
			if rollback {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.NoError(t, <-second)
			explicit := 1
			if mode == "user_a" || mode == "cm_a" || mode == "cross_owner_cm_a" {
				explicit = 0
			}
			require.Equal(t, explicit, asCount(t, h, id, "audit"))
			require.Zero(t, asCount(t, h, id, "business"))
			var cascades int
			require.NoError(t, db.QueryRow(`SELECT (SELECT count(*) FROM user_delete_audit_effects WHERE resource_type='auth_subject' AND resource_key=$1::text)+(SELECT count(*) FROM user_cmnr_delete_audit_events e, jsonb_array_elements(e.effects) f WHERE f->>'resource_type'='auth_subject' AND f->>'resource_numeric_id'=$1::text AND record_kind='success_witness')`, fmt.Sprint(id)).Scan(&cascades))
			if explicit == 1 {
				require.Zero(t, cascades)
			} else {
				require.Equal(t, 1, cascades)
			}
			t.Logf("real advisory wait: first_pid=%d second_pid=%d pre-entry business locks=%d mode=%s", pid1, pid2, businessLocks, mode)
		})
	}
}

type asSocketGate struct {
	armed                       atomic.Bool
	entered, release, finalized chan struct{}
	readOnce                    sync.Once
	commits                     atomic.Int32
}
type asGatedSocket struct {
	net.Conn
	gate *asSocketGate
}

func (c *asGatedSocket) Read(p []byte) (int, error) {
	if c.gate.armed.Load() {
		c.gate.readOnce.Do(func() { close(c.gate.entered) })
		<-c.gate.release
	}
	return c.Conn.Read(p)
}

type asSocketConnector struct {
	driver.Connector
	gate *asSocketGate
}

func (c asSocketConnector) Connect(ctx context.Context) (driver.Conn, error) {
	native, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &asSocketConn{Conn: native, gate: c.gate}, nil
}

type asSocketConn struct {
	driver.Conn
	gate *asSocketGate
}

func (c *asSocketConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
	if err != nil {
		return nil, err
	}
	return &asSocketTx{Tx: tx, gate: c.gate}, nil
}
func (c *asSocketConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	return c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, q)
}
func (c *asSocketConn) QueryContext(ctx context.Context, q string, v []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, v)
}
func (c *asSocketConn) ExecContext(ctx context.Context, q string, v []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, v)
}

type asSocketTx struct {
	driver.Tx
	gate *asSocketGate
}

func (tx *asSocketTx) Commit() error {
	tx.gate.commits.Add(1)
	tx.gate.armed.Store(true)
	err := tx.Tx.Commit()
	close(tx.gate.finalized)
	return err
}

func TestAuthSubjectDeleteRealLoopbackCommitResponseDelay(t *testing.T) {
	h := sd1Harness(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	ctx = permission.SystemContext(ctx, "Engine")
	var name string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&name))
	cfg, err := pgx.ParseConfig(harness.DBURL(name))
	require.NoError(t, err)
	gate := &asSocketGate{entered: make(chan struct{}), release: make(chan struct{}), finalized: make(chan struct{})}
	originalDial := cfg.DialFunc
	cfg.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := originalDial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &asGatedSocket{Conn: c, gate: gate}, nil
	}
	db := sql.OpenDB(asSocketConnector{Connector: stdlib.GetConnector(*cfg), gate: gate})
	defer db.Close()
	a := sd7App(h)
	a.DB = db
	a.UserStore, err = user.NewStore(ctx, db)
	require.NoError(t, err)
	owner := sd7User(t, h)
	id, subject := asSubject(t, h, owner, nil)
	result := make(chan error, 1)
	var once sync.Once
	release := func() { once.Do(func() { close(gate.release) }) }
	defer release()
	go func() {
		_, err := a.Mutation().DeleteAuthSubject(ctx, user.AuthSubject{UserID: owner, ProviderID: "SYNTHETIC_AUTH_PROVIDER", SubjectID: subject})
		result <- err
	}()
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal("real socket response read gate not reached")
	}
	// Independent real PG reads prove server durability while the original
	// native Commit is still blocked observing its socket response.
	require.Eventually(t, func() bool { return asCount(t, h, id, "audit") == 1 }, 2*time.Second, 10*time.Millisecond)
	require.Zero(t, asCount(t, h, id, "business"))
	var eventID, executionID, attemptID string
	require.NoError(t, h.App().DB().QueryRow(`SELECT event_id,execution_id,attempt_id FROM auth_subject_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, id).Scan(&eventID, &executionID, &attemptID))
	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(6 * time.Second):
		t.Fatal("Commit observation was not bounded")
	}
	var observations int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM auth_subject_delete_audit_events WHERE record_kind='attempt_observation'`).Scan(&observations))
	require.Zero(t, observations, "failure writer must not race unreleased business connection")
	require.EqualValues(t, 1, gate.commits.Load())
	release()
	select {
	case <-gate.finalized:
	case <-ctx.Done():
		t.Fatal("late native Commit did not finalize")
	}
	require.Equal(t, 1, asCount(t, h, id, "audit"))
	require.EqualValues(t, 1, gate.commits.Load())
	var exact int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM auth_subject_delete_audit_events WHERE event_id=$1 AND execution_id=$2 AND attempt_id=$3 AND root_id=$4 AND record_kind='success_witness'`, eventID, executionID, attemptID, id).Scan(&exact))
	require.Equal(t, 1, exact)
	t.Log("REAL PostgreSQL + loopback socket response delay: durable delete/audit observed before native Commit return; one Commit; release barrier held")
}

func TestAuthSubjectDeleteRealTimeoutAndDeadlock(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	var name string
	require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&name))
	for _, mode := range []string{"lock_timeout", "deadlock"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			ctx = permission.SystemContext(ctx, "Engine")
			owner := h.UUID("user-a")
			id, subject := asSubject(t, h, owner, nil)
			conn, err := db.Conn(ctx)
			require.NoError(t, err)
			defer conn.Close()
			parent, err := conn.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = parent.Rollback() }()
			var parentPID int
			require.NoError(t, parent.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&parentPID))
			connector, err := sd8PGConnector(harness.DBURL(name))
			require.NoError(t, err)
			owned := sql.OpenDB(connector)
			defer owned.Close()
			a := sd7App(h)
			a.DB = owned
			a.UserStore, err = user.NewStore(ctx, owned)
			require.NoError(t, err)
			if mode == "lock_timeout" {
				_, err = parent.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1297305411::integer,1396979713::integer)`)
				require.NoError(t, err)
				connector.beforeExec = func(ctx context.Context, c driver.Conn, q string, _ []driver.NamedValue) error {
					if strings.HasPrefix(q, "SELECT pg_advisory_xact_lock") {
						_, err := c.(driver.ExecerContext).ExecContext(ctx, `SET LOCAL lock_timeout='100ms'`, nil)
						return err
					}
					return nil
				}
				ok, err := a.Mutation().DeleteAuthSubject(ctx, user.AuthSubject{UserID: owner, ProviderID: "SYNTHETIC_AUTH_PROVIDER", SubjectID: subject})
				require.False(t, ok)
				require.Error(t, err)
				require.Equal(t, 1, asCount(t, h, id, "business"))
				require.Zero(t, asCount(t, h, id, "audit"))
				return
			}
			_, err = parent.ExecContext(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, owner)
			require.NoError(t, err)
			entered := make(chan int, 1)
			connector.afterEntry = func(ctx context.Context, c driver.Conn) error {
				pid, err := sd8NativePID(ctx, c)
				if err == nil {
					entered <- pid
				}
				return err
			}
			result := make(chan error, 1)
			go func() {
				_, err := a.Mutation().DeleteAuthSubject(ctx, user.AuthSubject{UserID: owner, ProviderID: "SYNTHETIC_AUTH_PROVIDER", SubjectID: subject})
				result <- err
			}()
			var pid int
			select {
			case pid = <-entered:
			case <-ctx.Done():
				t.Fatal("deadlock entry not reached")
			}
			require.Eventually(t, func() bool {
				var blocked bool
				return db.QueryRowContext(ctx, `SELECT $1=ANY(pg_blocking_pids($2))`, parentPID, pid).Scan(&blocked) == nil && blocked
			}, 2*time.Second, 10*time.Millisecond)
			_, parentErr := parent.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1297305411::integer,1396979713::integer)`)
			require.NoError(t, parent.Rollback())
			operationErr := <-result
			require.True(t, parentErr != nil || operationErr != nil, "real wait cycle must reject a victim")
			if operationErr != nil {
				require.Equal(t, 1, asCount(t, h, id, "business"))
				require.Zero(t, asCount(t, h, id, "audit"))
			} else {
				require.Zero(t, asCount(t, h, id, "business"))
				require.Equal(t, 1, asCount(t, h, id, "audit"))
			}
			t.Logf("real nonparticipant wait cycle: parent_pid=%d operation_pid=%d parent_rejected=%t operation_rejected=%t", parentPID, pid, parentErr != nil, operationErr != nil)
		})
	}
}

func TestAuthSubjectDeleteRealAttributionInterleaving(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	var name string
	require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&name))
	for _, mode := range []string{"update_before", "update_after", "missing_assignment_insert"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
			defer cancel()
			ctx = permission.SystemContext(ctx, "Engine")
			owner := h.UUID("user-a")
			oldOrg, newOrg := harness.SmokeOrganizationID, h.UUID("org-b")
			sd8Exec(t, h, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, owner, oldOrg)
			if mode == "missing_assignment_insert" {
				owner = sd7User(t, h)
			}
			id, subject := asSubject(t, h, owner, nil)
			connector, err := sd8PGConnector(harness.DBURL(name))
			require.NoError(t, err)
			owned := sql.OpenDB(connector)
			defer owned.Close()
			a := sd7App(h)
			a.DB = owned
			a.UserStore, err = user.NewStore(ctx, owned)
			require.NoError(t, err)
			entered := make(chan int, 1)
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			if mode == "update_before" {
				connector.afterEntry = func(ctx context.Context, c driver.Conn) error {
					pid, err := sd8NativePID(ctx, c)
					if err == nil {
						entered <- pid
					}
					return err
				}
			} else {
				connector.queryHook = func(ctx context.Context, c driver.Conn, q string, _ []driver.NamedValue) (driver.Rows, error, bool) {
					if strings.HasPrefix(q, "SELECT id,user_id,cm_id,xmin") {
						pid, err := sd8NativePID(ctx, c)
						if err != nil {
							return nil, err, true
						}
						entered <- pid
						select {
						case <-release:
						case <-ctx.Done():
							return nil, ctx.Err(), true
						}
					}
					return nil, nil, false
				}
			}
			conn, err := db.Conn(ctx)
			require.NoError(t, err)
			defer conn.Close()
			parent, err := conn.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = parent.Rollback() }()
			var parentPID int
			require.NoError(t, parent.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&parentPID))
			if mode == "update_before" {
				_, err = parent.ExecContext(ctx, `SELECT user_id FROM user_organization_assignments WHERE user_id=$1 FOR UPDATE`, owner)
				require.NoError(t, err)
			}
			result := make(chan error, 1)
			go func() {
				_, err := a.Mutation().DeleteAuthSubject(ctx, user.AuthSubject{UserID: owner, ProviderID: "SYNTHETIC_AUTH_PROVIDER", SubjectID: subject})
				result <- err
			}()
			var pid int
			select {
			case pid = <-entered:
			case <-ctx.Done():
				t.Fatal("attribution gate not reached")
			}
			expected := oldOrg
			switch mode {
			case "update_before":
				require.Eventually(t, func() bool {
					var blocked bool
					return db.QueryRowContext(ctx, `SELECT $1=ANY(pg_blocking_pids($2))`, parentPID, pid).Scan(&blocked) == nil && blocked
				}, 2*time.Second, 10*time.Millisecond)
				_, err = parent.ExecContext(ctx, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, owner, newOrg)
				require.NoError(t, err)
				require.NoError(t, parent.Commit())
				expected = newOrg
			case "update_after":
				updated := make(chan error, 1)
				go func() {
					_, err := parent.ExecContext(ctx, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, owner, newOrg)
					updated <- err
				}()
				require.Eventually(t, func() bool {
					var blocked bool
					return db.QueryRowContext(ctx, `SELECT $1=ANY(pg_blocking_pids($2))`, pid, parentPID).Scan(&blocked) == nil && blocked
				}, 2*time.Second, 10*time.Millisecond)
				unblock()
				require.NoError(t, <-result)
				require.NoError(t, <-updated)
				require.NoError(t, parent.Commit())
			default:
				_, err = parent.ExecContext(ctx, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count) SELECT $1,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count FROM user_organization_assignments WHERE user_id=$2`, owner, h.UUID("user-a"))
				require.NoError(t, err)
				require.NoError(t, parent.Commit())
				expected = "unknown"
				unblock()
			}
			if mode != "update_after" {
				require.NoError(t, <-result)
			}
			var target string
			require.NoError(t, db.QueryRow(`SELECT coalesce(target_organization_id::text,target_org_resolution) FROM auth_subject_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, id).Scan(&target))
			require.Equal(t, expected, target)
			t.Logf("real attribution interleaving=%s operation_pid=%d assignment_pid=%d", mode, pid, parentPID)
		})
	}
}
