package smoke

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth/authtoken"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

type usFaultRows struct {
	driver.Rows
	mode string
	seen bool
}

func (r *usFaultRows) Next(v []driver.Value) error {
	if r.mode == "rows_error" && r.seen {
		return errors.New("SYNTHETIC_PRIVATE_DRIVER")
	}
	err := r.Rows.Next(v)
	if err != nil {
		return err
	}
	r.seen = true
	if r.mode == "scan" {
		v[0] = "SYNTHETIC_PRIVATE_DRIVER"
	}
	return nil
}
func (r *usFaultRows) Close() error {
	err := r.Rows.Close()
	if r.mode == "close" {
		return errors.New("SYNTHETIC_PRIVATE_DRIVER")
	}
	return err
}

var _ io.Closer = (*usFaultRows)(nil)

func TestUserSessionAuditRealReceiptFaults(t *testing.T) {
	h := sd1Harness(t)
	var database string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&database))
	owner, otherOwner := sd7User(t, h), sd7User(t, h)
	for _, mode := range []string{"scan", "rows_error", "close", "attribution_change", "mutation_failed", "panic"} {
		t.Run(mode, func(t *testing.T) {
			id, safe := usSession(t, h, owner)
			connector, err := sd8PGConnector(harness.DBURL(database))
			require.NoError(t, err)
			if mode == "scan" || mode == "rows_error" || mode == "close" {
				connector.queryHook = func(ctx context.Context, native driver.Conn, q string, v []driver.NamedValue) (driver.Rows, error, bool) {
					if !strings.HasPrefix(q, "SELECT r.session_audit_id") {
						return nil, nil, false
					}
					rows, err := native.(driver.QueryerContext).QueryContext(ctx, q, v)
					if err != nil {
						return nil, err, true
					}
					return &usFaultRows{Rows: rows, mode: mode}, nil, true
				}
			}
			connector.beforeExec = func(ctx context.Context, native driver.Conn, q string, _ []driver.NamedValue) error {
				if !strings.HasPrefix(q, "WITH revoked AS") {
					return nil
				}
				if mode == "panic" {
					panic("SYNTHETIC_PRIVATE_DRIVER")
				}
				if mode == "mutation_failed" {
					_, err := native.(driver.ExecerContext).ExecContext(ctx, `SELECT 1/0`, nil)
					return err
				}
				if mode == "attribution_change" {
					_, err := native.(driver.ExecerContext).ExecContext(ctx, `UPDATE auth_user_sessions SET user_id=$2 WHERE id=$1`, []driver.NamedValue{{Ordinal: 1, Value: id}, {Ordinal: 2, Value: otherOwner}})
					return err
				}
				return nil
			}
			db := sql.OpenDB(connector)
			defer db.Close()
			a := sd7App(h)
			a.DB = db
			ok, err := a.Mutation().DeleteAll(permission.SystemContext(t.Context(), "Engine"), []assignment.RawTarget{{Type: assignment.TargetTypeUserSession, ID: id}})
			require.False(t, ok)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "SYNTHETIC_PRIVATE")
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1 AND user_id=$2`, id, owner))
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=$1`, safe))
			require.EqualValues(t, 1, connector.begins.Load()-1, "one business attempt plus one observation, no blind replay")
		})
	}
}
func TestUserSessionAuditRecreationAndNonCredentialIdentity(t *testing.T) {
	t.Log("RACE1_PHASE fixture_setup")
	f := globalOrganizationFixture(t)
	h := f.h
	id, safe := usSession(t, h, h.UUID("om"))
	t.Log("RACE1_PHASE raw_uuid_rejection")
	for _, raw := range []string{id, safe.String()} {
		status, _ := sd8HTTP(t, h, `mutation{endAllAuthSessionsByCurrentUser}`, raw)
		require.Equal(t, 401, status)
	}
	// A correctly signed token using the audit UUID cannot find a live Session.
	t.Log("RACE1_PHASE signed_audit_identity_rejection")
	signed := false
	token, err := (authtoken.Token{Version: 1, ID: safe, Type: authtoken.TypeSession}).Encode(func(payload []byte) ([]byte, error) {
		signed = true
		return h.App().SessionKeyring.Sign(payload)
	})
	require.NoError(t, err)
	require.True(t, signed, "audit identity credential must exercise the signer")
	status, _ := sd8HTTP(t, h, `mutation{endAllAuthSessionsByCurrentUser}`, token)
	require.Equal(t, 401, status)
	t.Log("RACE1_PHASE first_revoke")
	before := usSuccesses(t, h)
	usHTTP(t, f, "pam", usQuery(id), false)
	t.Log("RACE1_PHASE recreate_identity")
	var next string
	require.NoError(t, h.App().DB().QueryRow(`INSERT INTO auth_user_sessions(id,user_id) VALUES($1,$2) RETURNING audit_resource_id::text`, id, h.UUID("om")).Scan(&next))
	require.True(t, next != safe.String())
	t.Log("RACE1_PHASE second_revoke")
	usHTTP(t, f, "pam", usQuery(id), false)
	t.Log("RACE1_PHASE verify_lifecycles")
	require.Equal(t, before+2, usSuccesses(t, h))
	require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id::text=ANY($1)`, []string{safe.String(), next}))
	t.Log("RACE1_PHASE body_complete")
}
