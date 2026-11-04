package smoke

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/service"
	"github.com/target/goalert/service/updateaudit"
	"github.com/target/goalert/test/smoke/harness"
)

// Deliberately simulated driver acknowledgements around real PG transactions.
// These tests do NOT claim to reproduce a network disconnect or a lost packet.
type serviceAuditFaultConnector struct {
	base   driver.Connector
	mode   string
	begins atomic.Int64
}

func (c *serviceAuditFaultConnector) Driver() driver.Driver { return c.base.Driver() }
func (c *serviceAuditFaultConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &serviceAuditFaultConn{Conn: conn, c: c}, nil
}

type serviceAuditFaultConn struct {
	driver.Conn
	c *serviceAuditFaultConnector
}

func (c *serviceAuditFaultConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	n := c.c.begins.Add(1)
	if n == 1 && c.c.mode == "begin_failed" {
		return nil, errors.New("SYNTHETIC_CONNECTION_SECRET")
	}
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return serviceAuditFaultTx{Tx: tx, mode: c.c.mode, first: n == 1}, nil
}
func (c *serviceAuditFaultConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c *serviceAuditFaultConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}
func (c *serviceAuditFaultConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	return c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, q)
}

type serviceAuditFaultTx struct {
	driver.Tx
	mode  string
	first bool
}

func (t serviceAuditFaultTx) Commit() error {
	if t.first {
		switch t.mode {
		case "commit_then_error":
			if err := t.Tx.Commit(); err != nil {
				return err
			}
			return errors.New("SYNTHETIC_ACK_SECRET")
		case "completion_unknown":
			if err := t.Tx.Commit(); err != nil {
				return err
			}
			return &pgconn.PgError{Code: "40003", Message: "SYNTHETIC_COMPLETION_SECRET"}
		case "rollback_then_error":
			if err := t.Tx.Rollback(); err != nil {
				return err
			}
			return driver.ErrBadConn
		}
	}
	return t.Tx.Commit()
}
func (t serviceAuditFaultTx) Rollback() error {
	err := t.Tx.Rollback()
	if t.first && t.mode == "rollback_unconfirmed" && err == nil {
		return errors.New("SYNTHETIC_ROLLBACK_SECRET")
	}
	return err
}

func TestServiceUpdateAuditSimulatedCommitAcknowledgements(t *testing.T) {
	for _, mode := range []string{"commit_then_error", "rollback_then_error", "begin_failed", "rollback_unconfirmed", "completion_unknown"} {
		t.Run(mode, func(t *testing.T) {
			h := serviceAuditHarness(t)
			ikSetAuthority(t, h, "ORG_MEMBER", true)
			var name string
			require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&name))
			cfg, err := pgx.ParseConfig(harness.DBURL(name))
			require.NoError(t, err)
			c := &serviceAuditFaultConnector{base: stdlib.GetConnector(*cfg), mode: mode}
			db := sql.OpenDB(c)
			defer db.Close()
			store, err := service.NewStore(context.Background(), db)
			require.NoError(t, err)
			a := graphqlapp.App{DB: db, ServiceStore: store}
			description := "synthetic fault update"
			input := graphql2.UpdateServiceInput{ID: h.UUID("service-b"), Description: &description}
			if mode == "rollback_unconfirmed" {
				bad := ""
				input.Name = &bad
			}
			ok, err := a.Mutation().UpdateService(servicePlatformAdminContext(t, h), input)
			require.Error(t, err)
			require.False(t, ok, "Commit error never reports resolver success")
			require.NotContains(t, err.Error(), "SYNTHETIC_")
			var committed, unknown, failed, rollback int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FILTER(WHERE outcome='committed'),count(*) FILTER(WHERE outcome='commit_unknown'),count(*) FILTER(WHERE outcome='tx_failed'),count(*) FILTER(WHERE outcome='rollback_unconfirmed') FROM service_update_audit_events`).Scan(&committed, &unknown, &failed, &rollback))
			var actual string
			require.NoError(t, h.App().DB().QueryRow(`SELECT description FROM services WHERE id=$1`, h.UUID("service-b")).Scan(&actual))
			switch mode {
			case "commit_then_error", "completion_unknown":
				require.Equal(t, description, actual)
				require.Equal(t, 1, committed)
				require.Equal(t, 1, unknown)
			case "rollback_then_error":
				require.Empty(t, actual)
				require.Zero(t, committed)
				require.Equal(t, 1, unknown)
			case "begin_failed":
				require.Empty(t, actual)
				require.Equal(t, 1, failed)
			case "rollback_unconfirmed":
				require.Empty(t, actual)
				require.Equal(t, 1, rollback)
			}
			require.EqualValues(t, 2, c.begins.Load(), "one business attempt and one failure transaction; no mutation replay")
			rows := serviceAuditRows(t, h)
			require.NotContains(t, rows, "SYNTHETIC_")
			if mode == "commit_then_error" || mode == "completion_unknown" {
				var attempts int
				require.NoError(t, h.App().DB().QueryRow(`SELECT count(DISTINCT attempt_id) FROM service_update_audit_events`).Scan(&attempts))
				require.Equal(t, 1, attempts, "success witness and uncertainty observation correlate without overwriting")
			}
		})
	}
}

func TestServiceUpdateAuditRealCommitRejection(t *testing.T) {
	h := serviceAuditHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	_, err := h.App().DB().Exec(`CREATE FUNCTION audit_test_commit_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='SYNTHETIC_DEFERRED_SECRET'; END $$;
CREATE CONSTRAINT TRIGGER audit_test_commit_reject AFTER UPDATE ON services DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION audit_test_commit_reject()`)
	require.NoError(t, err)
	before := serviceManagementSnapshot(t, h)
	wait := h.ExpectBackendError("service.update transaction failed")
	r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"deferred failure"})}`, h.UUID("service-b")))
	wait()
	require.NotEmpty(t, r.Errors)
	require.Equal(t, before, serviceManagementSnapshot(t, h))
	var outcome, reason string
	require.NoError(t, h.App().DB().QueryRow(`SELECT outcome,reason_code FROM service_update_audit_events`).Scan(&outcome, &reason))
	require.Equal(t, "tx_failed", outcome)
	require.Equal(t, "commit_rejected", reason)
	require.NotContains(t, serviceAuditRows(t, h), "SYNTHETIC_DEFERRED_SECRET")
}

func TestServiceUpdateAuditFailurePersistenceLimits(t *testing.T) {
	h := serviceAuditHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	_, err := h.App().DB().Exec(`CREATE FUNCTION audit_test_sink_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SYNTHETIC_SINK_SECRET'; END $$;
CREATE TRIGGER audit_test_sink_fail BEFORE INSERT ON service_update_audit_events FOR EACH ROW EXECUTE FUNCTION audit_test_sink_fail()`)
	require.NoError(t, err)
	wait := h.ExpectBackendError("service.update audit persistence unavailable")
	r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"denied during outage"})}`, h.UUID("service-b")))
	wait()
	require.NotEmpty(t, r.Errors)
	require.Contains(t, fmt.Sprint(r.Errors), "audit persistence unavailable")
	require.Zero(t, serviceAuditCount(t, h), "a failed independent append must not claim durable denial")
	_, err = h.App().DB().Exec(`DROP TRIGGER audit_test_sink_fail ON service_update_audit_events`)
	require.NoError(t, err)
	e := updateaudit.Event{EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorKind: "unknown", AuthoritySource: "unknown", AuthorityRole: "unknown", OrganizationRole: "unknown", Outcome: "denied", Reason: "authority_denied", OccurredAt: time.Now()}
	tx, err := h.App().DB().Begin()
	require.NoError(t, err)
	_, err = tx.Exec(`LOCK TABLE service_update_audit_events IN SHARE MODE`)
	require.NoError(t, err)
	start := time.Now()
	err = updateaudit.RecordFailure(h.App().DB(), e)
	require.ErrorIs(t, err, updateaudit.ErrUnavailable)
	require.Less(t, time.Since(start), 4*time.Second, "independent append has a finite budget")
	require.NoError(t, tx.Rollback())
	require.Zero(t, serviceAuditCount(t, h))
	require.NoError(t, updateaudit.RecordFailure(h.App().DB(), e))
	require.Equal(t, 1, serviceAuditCount(t, h))
	var name string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&name))
	cfg, err := pgx.ParseConfig(harness.DBURL(name))
	require.NoError(t, err)
	closed := sql.OpenDB(stdlib.GetConnector(*cfg))
	require.NoError(t, closed.Close())
	require.ErrorIs(t, updateaudit.RecordFailure(closed, e), updateaudit.ErrUnavailable)
	t.Log("closed-pool unavailable control; no production/whole-server disconnect experiment claimed")
}
