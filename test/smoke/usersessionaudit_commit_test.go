package smoke

import (
	"context"
	"database/sql"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

// This wraps a real PostgreSQL connection. It drops the actual COMMIT response
// after an independent connection has proved the deletion and witness durable.
// This is a transport fault, not a mock successful transaction.
type usLostCommitResponse struct {
	net.Conn
	gate *asSocketGate
}

func (c *usLostCommitResponse) Read(p []byte) (int, error) {
	if c.gate.armed.Load() {
		c.gate.readOnce.Do(func() { close(c.gate.entered) })
		<-c.gate.release
		_ = c.Close()
		return 0, net.ErrClosed
	}
	return c.Conn.Read(p)
}
func TestUserSessionAuditRealCommitUnknown(t *testing.T) {
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	var database string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&database))
	for _, mode := range []string{"selected", "end_all"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			owner := h.UUID("user-a")
			current, _ := usSession(t, h, owner)
			other, safe := usSession(t, h, owner)
			if mode == "selected" {
				ctx = permission.SystemContext(ctx, "Engine")
			} else {
				ctx = permission.UserSourceContext(h.Config().Context(ctx), owner, permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: current})
				requester, err := auth.NewRequester(owner, current)
				require.NoError(t, err)
				ctx = auth.WithRequester(ctx, requester)
				constructor, err := executioncontext.NewHumanExecutionContextConstructor(h.App().OrganizationStore)
				require.NoError(t, err)
				ec, err := constructor.Construct(ctx)
				require.NoError(t, err)
				ctx = executioncontext.WithExecutionContext(ctx, ec)
			}
			cfg, err := pgx.ParseConfig(harness.DBURL(database))
			require.NoError(t, err)
			gate := &asSocketGate{entered: make(chan struct{}), release: make(chan struct{}), finalized: make(chan struct{})}
			dial := cfg.DialFunc
			cfg.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
				native, err := dial(ctx, network, address)
				if err != nil {
					return nil, err
				}
				return &usLostCommitResponse{Conn: native, gate: gate}, nil
			}
			db := sql.OpenDB(asSocketConnector{Connector: stdlib.GetConnector(*cfg), gate: gate})
			defer db.Close()
			a := sd7App(h)
			a.DB = db
			var once sync.Once
			release := func() { once.Do(func() { close(gate.release) }) }
			defer release()
			result := make(chan error, 1)
			go func() {
				if mode == "selected" {
					_, err := a.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeUserSession, ID: other}})
					result <- err
				} else {
					_, err := a.Mutation().EndAllAuthSessionsByCurrentUser(ctx)
					result <- err
				}
			}()
			select {
			case <-gate.entered:
			case <-ctx.Done():
				t.Fatal("COMMIT response boundary not reached")
			}
			require.Eventually(t, func() bool {
				return sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=$1`, safe) == 1
			}, time.Second, 10*time.Millisecond)
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1`, other))
			newSession, _ := usSession(t, h, owner)
			select {
			case err := <-result:
				require.Error(t, err)
			case <-time.After(6 * time.Second):
				t.Fatal("unknown observation did not return in bounded time")
			}
			require.EqualValues(t, 1, gate.commits.Load())
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_events WHERE record_kind='attempt_observation'`), "unreleased business connection forbids a competing observation writer")
			release()
			select {
			case <-gate.finalized:
			case <-ctx.Done():
				t.Fatal("late Commit was not finalized")
			}
			require.EqualValues(t, 1, gate.commits.Load())
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1`, newSession))
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=$1`, safe))
		})
	}
}
