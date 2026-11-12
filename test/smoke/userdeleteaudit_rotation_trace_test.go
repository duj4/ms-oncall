package smoke

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func TestUserDeleteAuditRotationTrace(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	var name string
	require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&name))
	for _, shape := range []string{"UVW", "UUVW", "UVUW", "UUU"} {
		for active := range len(shape) {
			t.Run(fmt.Sprintf("%s/active_%d", shape, active), func(t *testing.T) {
				u, v, w := sd7User(t, h), sd7User(t, h), sd7User(t, h)
				lookup := map[byte]string{'U': u, 'V': v, 'W': w}
				rot := sd6Root(t, h, "rotation", harness.SmokeOrganizationID)
				ids := make([]string, len(shape))
				for i, ch := range []byte(shape) {
					ids[i] = uuid.NewString()
					sd8Exec(t, h, `INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES($1,$2,$3,$4)`, ids[i], rot, lookup[ch], i)
				}
				sd8Exec(t, h, `UPDATE rotation_state SET rotation_participant_id=$2,position=$3 WHERE rotation_id=$1`, rot, ids[active], active)
				expected := []string{}
				skipped := false
				curIndex, activeIndex := -1, active
				for i, ch := range []byte(shape) {
					if ch == 'U' {
						if i < activeIndex {
							activeIndex--
						}
						skipped = true
						continue
					}
					curIndex++
					if skipped {
						expected = append(expected, "update:"+ids[curIndex])
					}
				}
				if activeIndex > curIndex {
					activeIndex = 0
				}
				for i := len(shape) - 1; i > curIndex; i-- {
					expected = append(expected, "delete:"+ids[i])
				}
				connector, err := sd8PGConnector(harness.DBURL(name))
				require.NoError(t, err)
				controlled := sql.OpenDB(connector)
				defer controlled.Close()
				app := sd7App(h)
				app.DB = controlled
				ok, err := app.Mutation().DeleteAll(permission.SystemContext(t.Context(), "Engine"), []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}})
				require.NoError(t, err)
				require.True(t, ok)
				connector.mu.Lock()
				actual := append([]string{}, connector.trace...)
				connector.mu.Unlock()
				require.Equal(t, expected, actual, "actual native UPDATE and reverse DELETE call order")
				require.EqualValues(t, 1, connector.begins.Load())
				require.EqualValues(t, 1, connector.commits.Load())
				if curIndex < 0 {
					require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM rotation_state WHERE rotation_id=$1`, rot))
				} else {
					var part string
					var position int
					require.NoError(t, db.QueryRow(`SELECT rotation_participant_id,position FROM rotation_state WHERE rotation_id=$1`, rot).Scan(&part, &position))
					require.Equal(t, ids[activeIndex], part)
					require.Equal(t, activeIndex, position)
				}
				t.Log("native_trace", actual, "expected_active_index", activeIndex)
			})
		}
	}
}
