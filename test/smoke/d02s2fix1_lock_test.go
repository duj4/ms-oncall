package smoke

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/organization"
)

// Observe actual PostgreSQL blocking, then invalidate the target under the
// independent transaction. The request must re-read the persistent relationship.
func TestD02S2Fix1ContactMethodAssignmentLocks(t *testing.T) {
	for _, operation := range []string{"create", "update"} {
		t.Run(operation, func(t *testing.T) {
			f := s2New(t)
			db := f.h.App().DB()
			blocker, err := db.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer func() { _ = blocker.Rollback() }()
			var pid int
			require.NoError(t, blocker.QueryRowContext(t.Context(), `SELECT pg_backend_pid()`).Scan(&pid))
			_, err = blocker.ExecContext(t.Context(), `SELECT user_id FROM user_organization_assignments WHERE user_id=$1 FOR UPDATE`, f.h.UUID("b"))
			require.NoError(t, err)
			before := s2Snapshot(t, f)
			query := fmt.Sprintf(`mutation{createUserContactMethod(input:{userID:%q,name:"FIX1 locked",type:EMAIL,value:"fix1-lock@example.invalid"}){id}}`, f.h.UUID("b"))
			if operation == "update" {
				query = fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,name:"FIX1 locked"})}`, f.h.UUID("cm-b"))
			}
			result := make(chan *s2Result, 1)
			go func() {
				var r *s2Result
				defer func() { result <- r }()
				r = s2Call(t, f, "signed-HTTP-assignment-wait", "pam", query, nil)
			}()
			observed := false
			var waits string
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				waits = s2Rows(t, f, `SELECT pid,wait_event_type,wait_event,pg_blocking_pids(pid) AS blockers
					FROM pg_stat_activity WHERE datname=current_database()
					AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid))`, pid)
				if waits != "[]" {
					observed = true
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			_, changeErr := blocker.ExecContext(t.Context(), `UPDATE user_organization_assignments
				SET effective_organization_id=$2,effective_organization_classification='DEFAULT',
					effective_normal_organization_id=NULL,organization_role='NONE',
					mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`,
				f.h.UUID("b"), organization.DefaultOrganizationID)
			commitErr := blocker.Commit()
			// Always release and join before checking results.
			var r *s2Result
			select {
			case r = <-result:
			case <-time.After(25 * time.Second):
				t.Fatal("signed HTTP worker did not finish after target lock release")
			}
			require.NoError(t, changeErr)
			require.NoError(t, commitErr)
			require.True(t, observed, "observe the actual independent PostgreSQL blocker")
			require.NotNil(t, r)
			s2Deny(t, r)
			after := s2Snapshot(t, f)
			// This one change belongs to the test's independent transaction.
			expected := before
			expected["user_organization_assignments"] = after["user_organization_assignments"]
			require.Equal(t, expected, after, "the rejected HTTP mutation has no persistent side effects")
			s2Save(t, "target-lock-proof", map[string]any{
				"operation": operation, "blocker_pid": pid, "observed_waits": waits,
				"controlled_fixture_change": "B target Assignment moved to Default by independent blocker",
				"after":                     after, "http_mutation_side_effects": false,
			})
		})
	}
}
