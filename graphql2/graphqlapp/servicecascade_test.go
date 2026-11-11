package graphqlapp

import (
	"context"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/retry"
	"github.com/target/goalert/service"
	"github.com/target/goalert/service/deleteaudit"
)

type sd3Rows struct {
	names  []string
	values [][]driver.Value
}

func (r *sd3Rows) Columns() []string { return r.names }
func (*sd3Rows) Close() error        { return nil }
func (r *sd3Rows) Next(out []driver.Value) error {
	if len(r.values) == 0 {
		return io.EOF
	}
	copy(out, r.values[0])
	r.values = r.values[1:]
	return nil
}
func (c *sd2Conn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	if q == "SHOW transaction_isolation" {
		return &sd3Rows{[]string{"isolation"}, [][]driver.Value{{"read committed"}}}, nil
	}
	if strings.HasPrefix(q, "SELECT EXISTS(SELECT FROM integration_keys WHERE audit_resource_id=") {
		return &sd3Rows{[]string{"exists"}, [][]driver.Value{{false}}}, nil
	}
	if strings.Contains(q, "FROM escalation_policy_delete_audit_events") {
		return &sd3Rows{[]string{"roots", "effects", "bytes"}, [][]driver.Value{{int64(c.tx.eps), int64(0), int64(c.tx.eps * 2)}}}, nil
	}
	if strings.Contains(q, "sum(jsonb_array_length(effects))") {
		return &sd3Rows{[]string{"roots", "effects", "bytes"}, [][]driver.Value{{int64(c.tx.services), int64(0), int64(c.tx.services * 2)}}}, nil
	}
	if strings.HasPrefix(c.s.mode, "cascade:") {
		parts := strings.Split(c.s.mode, ":")
		stage := parts[1]
		code := parts[2]
		matched := stage == "root_lock" && strings.HasPrefix(q, "SELECT id FROM services") || stage == "child_lock" && strings.Contains(q, "FROM integration_keys") && strings.Contains(q, "FOR UPDATE") || stage == "membership" && strings.Contains(q, "COALESCE(id=ANY") || stage == "post_check" && strings.Contains(q, "SELECT EXISTS(SELECT FROM services")
		c.s.mu.Lock()
		n := c.s.deletes
		c.s.mu.Unlock()
		if matched && (n <= 2 || parts[3] == "exhaust") {
			return nil, &pgconn.PgError{Code: code, Message: "SYNTHETIC_SECRET"}
		}
		if strings.HasPrefix(q, "SELECT id FROM services") {
			return &sd3Rows{[]string{"id"}, [][]driver.Value{{c.s.cascadeRoot.String()}}}, nil
		}
		if strings.HasPrefix(q, "SELECT id,organization_id FROM services") {
			return &sd3Rows{[]string{"id", "org"}, [][]driver.Value{{c.s.cascadeRoot.String(), c.s.cascadeOrg.String()}}}, nil
		}
		if strings.HasPrefix(q, "SELECT EXISTS(SELECT FROM services") {
			return &sd3Rows{[]string{"exists", "unchanged"}, [][]driver.Value{{false, false}}}, nil
		}
		if strings.HasPrefix(q, "SELECT count(*)") {
			return &sd3Rows{[]string{"n"}, [][]driver.Value{{int64(0)}}}, nil
		}
		if strings.HasPrefix(q, "SELECT EXISTS") {
			return &sd3Rows{[]string{"exists"}, [][]driver.Value{{false}}}, nil
		}
		return &sd3Rows{[]string{"empty"}, nil}, nil
	}
	return nil, io.ErrUnexpectedEOF
}

func TestServiceCascadeBusinessAbortVersusIntegrity(t *testing.T) {
	for _, code := range []string{"40001", "40P01", "23514", "42703", "42501", "08006"} {
		t.Run(code, func(t *testing.T) {
			a := &serviceDeleteAttempt{}
			err := &pgconn.PgError{Code: code, Message: "SYNTHETIC_SECRET", Detail: "SYNTHETIC_SECRET", Hint: "SYNTHETIC_SECRET"}
			require.Same(t, err, a.captureError(err))
			require.Equal(t, code != "40001" && code != "40P01", a.auditFailed)
			require.Error(t, a.captureError(deleteaudit.ErrInvalid))
			require.Error(t, a.captureError(err))
			require.True(t, a.auditFailed, "a later abort cannot erase integrity failure")
			require.NotContains(t, serviceDeleteSafeError(err).Error(), "SYNTHETIC_")
		})
	}
}

func TestServiceCascadeD06FailureWriterAbortDoesNotAuthorizeRetry(t *testing.T) {
	for _, stage := range []string{"begin", "append", "commit"} {
		for _, code := range []string{"40001", "40P01"} {
			t.Run(stage+code, func(t *testing.T) {
				s := &sd2State{mode: "failure_" + stage + "_pg:" + code}
				p := sd2Plan(t, s, true)
				err := retry.DoTemporaryError(func(int) error { return sd2Attempt(t, p) }, retry.Limit(5))
				require.Error(t, err)
				require.False(t, retry.IsTemporaryError(err))
				require.NotContains(t, err.Error(), "SYNTHETIC_")
				s.mu.Lock()
				defer s.mu.Unlock()
				require.Equal(t, 1, s.deletes)
				require.Equal(t, 2, s.begins)
			})
		}
	}
}

func TestServiceCascadeD05OriginalCaptureSQLAbortUsesExistingRetryGate(t *testing.T) {
	for _, stage := range []string{"root_lock", "child_lock", "membership", "post_check"} {
		for _, code := range []string{"40001", "40P01"} {
			for _, mode := range []string{"recover", "exhaust"} {
				t.Run(fmt.Sprintf("%s/%s/%s", stage, code, mode), func(t *testing.T) {
					s := &sd2State{mode: "cascade:" + stage + ":" + code + ":" + mode, cascadeRoot: uuid.New(), cascadeOrg: uuid.New()}
					p := sd2Plan(t, s, true)
					err := retry.DoTemporaryError(func(int) error {
						a := p.nextAttempt()
						tx, err := a.begin(t.Context())
						if err != nil {
							return a.finish(err)
						}
						_, err = tx.ExecContext(t.Context(), "SD2 synthetic delete")
						if err == nil {
							err = a.capture(t.Context(), []string{s.cascadeRoot.String()}, nil)
						}
						if err == nil {
							a.service.deletedRoots = []service.DeletedService{{ID: s.cascadeRoot, OrganizationID: s.cascadeOrg}}
							err = a.witness(t.Context())
						}
						if err == nil {
							err = a.commit(t.Context())
						}
						require.False(t, a.auditFailed, "a confirmed original SQL abort alone is not an audit integrity failure")
						return a.finish(err)
					}, retry.Limit(5))
					s.mu.Lock()
					defer s.mu.Unlock()
					if mode == "recover" {
						require.NoError(t, err)
						require.Equal(t, 3, s.deletes)
						require.Equal(t, 1, s.commits)
					} else {
						require.Error(t, err)
						require.Equal(t, 5, s.deletes)
						require.Zero(t, s.commits)
					}
					require.NotZero(t, s.observations)
				})
			}
		}
	}
}

func TestServiceCascadeD06AuditAppendAbortStillBlocksRetry(t *testing.T) {
	for _, code := range []string{"40001", "40P01"} {
		t.Run(code, func(t *testing.T) {
			s := &sd2State{mode: "cascade:append:" + code + ":exhaust", cascadeRoot: uuid.New(), cascadeOrg: uuid.New()}
			p := sd2Plan(t, s, true)
			err := retry.DoTemporaryError(func(int) error {
				a := p.nextAttempt()
				tx, err := a.begin(t.Context())
				if err != nil {
					return a.finish(err)
				}
				_, err = tx.ExecContext(t.Context(), "SD2 synthetic delete")
				if err == nil {
					err = a.capture(t.Context(), []string{s.cascadeRoot.String()}, nil)
				}
				if err == nil {
					a.service.deletedRoots = []service.DeletedService{{ID: s.cascadeRoot, OrganizationID: s.cascadeOrg}}
					err = a.witness(t.Context())
				}
				require.True(t, a.auditFailed, "Append errors retain the existing sink failure boundary")
				return a.finish(err)
			}, retry.Limit(5))
			require.Error(t, err)
			require.False(t, retry.IsTemporaryError(err))
			require.NotContains(t, err.Error(), "SYNTHETIC_")
			s.mu.Lock()
			defer s.mu.Unlock()
			require.Equal(t, 1, s.deletes)
			require.Zero(t, s.commits)
			require.Greater(t, s.observations, 0)
		})
	}
}
