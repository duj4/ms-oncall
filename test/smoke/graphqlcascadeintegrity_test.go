package smoke

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/test/smoke/harness"
)

// These synthetic historical relationships satisfy the real constraints. The
// ordinary API is never used to create a cross-Organization Action.
func lc1Harness(t *testing.T, kind string, foreign bool) *harness.Harness {
	t.Helper()
	step := "step-a1"
	if foreign {
		step = "step-b1"
	}
	h := harness.NewHarness(t, stepActionOrganizationSQL+fmt.Sprintf(`
		INSERT INTO escalation_policy_actions (id, escalation_policy_step_id, %s_id)
		VALUES ({{uuid "lc1-action"}}, {{uuid %q}}, {{uuid %q}});
		INSERT INTO schedule_rules (schedule_id, tgt_rotation_id)
		VALUES ({{uuid "schedule-a"}}, {{uuid "rotation-a"}});
	`, kind, step, kind+"-a"), "")
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	return h
}

func lc1Delete(h *harness.Harness, targets ...string) string {
	var input []string
	for _, target := range targets {
		kind, _, _ := strings.Cut(target, "-")
		input = append(input, fmt.Sprintf(`{type:%s,id:%q}`, kind, h.UUID(target)))
	}
	return `mutation{deleteAll(input:[` + strings.Join(input, ",") + `])}`
}

func lc1Evidence(t *testing.T, h *harness.Harness, before, after map[string]string, response *stepOrganizationResponse) {
	t.Helper()
	if os.Getenv("D08_LC1_EVIDENCE") == "" {
		return
	}
	var actorID, home, homeRole, platformRole string
	require.NoError(t, h.App().DB().QueryRow(`
		SELECT u.id, a.effective_organization_id, a.organization_role, u.role
		FROM users u JOIN user_organization_assignments a ON a.user_id=u.id WHERE u.id=$1
	`, h.UUID("user-a")).Scan(&actorID, &home, &homeRole, &platformRole))
	rows, err := h.App().DB().Query(`SELECT conname, pg_get_constraintdef(oid)
		FROM pg_constraint WHERE contype='f' AND conrelid IN
		('escalation_policy_actions'::regclass, 'escalation_policy_steps'::regclass, 'schedule_rules'::regclass)
		ORDER BY conrelid, conname`)
	require.NoError(t, err)
	var constraints [][2]string
	for rows.Next() {
		var row [2]string
		require.NoError(t, rows.Scan(&row[0], &row[1]))
		constraints = append(constraints, row)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	data, err := json.MarshalIndent(map[string]any{
		"test": t.Name(), "actual_actor_type": "signed Human session", "actor_id": actorID,
		"home_organization": home, "home_role": homeRole, "persisted_user_role": platformRole,
		"http_status": 200, "graphql_response": response, "before": before, "after": after,
		"runtime_constraints": constraints,
	}, "", "  ")
	require.NoError(t, err)
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + ".json"
	require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("D08_LC1_EVIDENCE"), name), append(data, '\n'), 0600))
}

func TestD08LC1ForeignDependentDelete(t *testing.T) {
	for _, kind := range []string{"schedule", "rotation"} {
		t.Run(kind, func(t *testing.T) {
			h := lc1Harness(t, kind, true)
			before := stepOrganizationSnapshot(t, h)
			wait := h.ExpectBackendError("sql: no rows in result set")
			response := stepOrganizationQuery(t, h, lc1Delete(h, kind+"-a"))
			after := stepOrganizationSnapshot(t, h)
			lc1Evidence(t, h, before, after, response)
			assert.Len(t, response.Errors, 1, "foreign EP configuration must prevent deletion")
			assert.Equal(t, before, after, "the entire durable business state must remain unchanged")
			if len(response.Errors) > 0 {
				wait()
			}
		})
	}
}

func TestD08LC1SameOrganizationCascade(t *testing.T) {
	for _, kind := range []string{"schedule", "rotation"} {
		t.Run(kind, func(t *testing.T) {
			h := lc1Harness(t, kind, false)
			before := stepOrganizationSnapshot(t, h)
			// Duplicate targets remain a single valid deletion.
			response := stepOrganizationQuery(t, h, lc1Delete(h, kind+"-a", kind+"-a"))
			after := stepOrganizationSnapshot(t, h)
			lc1Evidence(t, h, before, after, response)
			require.Empty(t, response.Errors)
			var count int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM escalation_policy_actions WHERE id=$1`, h.UUID("lc1-action")).Scan(&count))
			require.Zero(t, count)
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM `+kind+`s WHERE id=$1`, h.UUID(kind+"-a")).Scan(&count))
			require.Zero(t, count)
			for _, table := range []string{"escalation_policies", "escalation_policy_steps"} {
				require.Equal(t, before[table], after[table], "EP roots and Steps must be preserved")
			}
			var oldActions, newActions []map[string]any
			require.NoError(t, json.Unmarshal([]byte(before["escalation_policy_actions"]), &oldActions))
			require.NoError(t, json.Unmarshal([]byte(after["escalation_policy_actions"]), &newActions))
			var remaining []map[string]any
			for _, action := range oldActions {
				if action["id"] != h.UUID("lc1-action") {
					remaining = append(remaining, action)
				}
			}
			require.ElementsMatch(t, remaining, newActions, "every unrelated Action must remain byte-equivalent")
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM `+kind+`s WHERE id=$1`, h.UUID(kind+"-b")).Scan(&count))
			require.Equal(t, 1, count, "the unrelated foreign root must survive")
		})
	}
}

func TestD08LC1DeleteBatchRollback(t *testing.T) {
	for _, kind := range []string{"schedule", "rotation"} {
		for _, batch := range []string{"foreign dependency", "missing root", "foreign root", "late missing EP"} {
			t.Run(kind+"/"+batch, func(t *testing.T) {
				h := lc1Harness(t, kind, batch == "foreign dependency")
				targets := []string{"rotation-a2", "schedule-a2", kind + "-a"}
				switch batch {
				case "missing root":
					targets = append(targets, kind+"-missing")
				case "foreign root":
					targets = append(targets, kind+"-b")
				case "late missing EP":
					targets = append(targets, "escalationPolicy-missing")
				}
				before := stepOrganizationSnapshot(t, h)
				wait := h.ExpectBackendError("sql: no rows in result set")
				response := stepOrganizationQuery(t, h, lc1Delete(h, targets...))
				after := stepOrganizationSnapshot(t, h)
				lc1Evidence(t, h, before, after, response)
				require.Len(t, response.Errors, 1)
				wait()
				require.Equal(t, before, after, "every target group must roll back")
			})
		}
	}
}

func TestD08LC1ScheduleDoesNotDeleteRotation(t *testing.T) {
	h := lc1Harness(t, "rotation", true)
	before := stepOrganizationSnapshot(t, h)
	response := stepOrganizationQuery(t, h, lc1Delete(h, "schedule-a"))
	after := stepOrganizationSnapshot(t, h)
	lc1Evidence(t, h, before, after, response)
	require.Empty(t, response.Errors)
	for _, table := range []string{"rotations", "escalation_policy_actions", "escalation_policy_steps", "escalation_policies"} {
		require.Equal(t, before[table], after[table], "Schedule rules reference independent Rotations; they are not child roots")
	}
	require.NotEqual(t, before["schedule_rules"], after["schedule_rules"])
}

func TestD08LC1ValidMixedBatch(t *testing.T) {
	h := lc1Harness(t, "rotation", false)
	response := stepOrganizationQuery(t, h, lc1Delete(h, "rotation-a", "schedule-a", "rotation-a2", "schedule-a2"))
	require.Empty(t, response.Errors)
	var count int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM schedules WHERE organization_id=$1`, harness.SmokeOrganizationID).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM rotations WHERE organization_id=$1`, harness.SmokeOrganizationID).Scan(&count))
	require.Zero(t, count)
}

func TestD08LC1PlatformAdminForeignDependency(t *testing.T) {
	for _, kind := range []string{"schedule", "rotation"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			h := lc1Harness(t, kind, true)
			_, err := h.App().DB().Exec(`UPDATE users SET role='admin' WHERE id=$1`, h.UUID("user-a"))
			require.NoError(t, err)
			before := stepOrganizationSnapshot(t, h)
			wait := h.ExpectBackendError("sql: no rows in result set")
			response := stepOrganizationQuery(t, h, lc1Delete(h, kind+"-a"))
			after := stepOrganizationSnapshot(t, h)
			lc1Evidence(t, h, before, after, response)
			require.Len(t, response.Errors, 1)
			wait()
			require.Equal(t, before, after, "PlatformAdmin still uses the current concrete Home scope")
		})
	}
}

func lc1Connection(t *testing.T, ctx context.Context, h *harness.Harness) *pgx.Conn {
	t.Helper()
	pooled, err := h.App().DB().Conn(ctx)
	require.NoError(t, err)
	var config *pgx.ConnConfig
	err = pooled.Raw(func(raw any) error {
		config = raw.(*stdlib.Conn).Conn().Config()
		return nil
	})
	require.NoError(t, pooled.Close())
	require.NoError(t, err)
	conn, err := pgx.ConnectConfig(ctx, config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

type lc1HTTPResult struct {
	response stepOrganizationResponse
	status   int
	err      error
}

func lc1Request(t *testing.T, ctx context.Context, h *harness.Harness, wg *sync.WaitGroup, query string) <-chan lc1HTTPResult {
	t.Helper()
	body, err := json.Marshal(map[string]string{"query": query})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: h.GraphQLToken(h.UUID("user-a"))})
	done := make(chan lc1HTTPResult, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var result lc1HTTPResult
		resp, err := http.DefaultClient.Do(req)
		result.err = err
		if err == nil {
			defer resp.Body.Close()
			result.status = resp.StatusCode
			result.err = json.NewDecoder(resp.Body).Decode(&result.response)
		}
		done <- result
	}()
	return done
}

func lc1BlockedBy(t *testing.T, ctx context.Context, observer *pgx.Conn, blocker int) int {
	t.Helper()
	var pid int
	var queryErr error
	require.Eventually(t, func() bool {
		queryErr = observer.QueryRow(ctx, `SELECT coalesce(max(pid),0) FROM pg_stat_activity
			WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, blocker).Scan(&pid)
		return queryErr == nil && pid != 0
	}, 5*time.Second, 10*time.Millisecond, "expected a real PostgreSQL lock wait")
	require.NoError(t, queryErr)
	return pid
}

func TestD08LC1ConcurrentDependency(t *testing.T) {
	for _, kind := range []string{"schedule", "rotation"} {
		for _, order := range []string{"dependency first", "deletion first"} {
			t.Run(kind+"/"+order, func(t *testing.T) {
				t.Parallel()
				h := lc1Harness(t, kind, false)
				before := stepOrganizationSnapshot(t, h)
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				writer := lc1Connection(t, ctx, h)
				observer := lc1Connection(t, ctx, h)
				gate, err := writer.Begin(ctx)
				require.NoError(t, err)
				var requests sync.WaitGroup
				defer func() {
					_ = gate.Rollback(context.Background())
					cancel()
					requests.Wait()
				}()
				insert := `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,` + kind + `_id) VALUES($1,$2,$3)`
				args := []any{h.UUID("lc1-concurrent-action"), h.UUID("step-b1"), h.UUID(kind + "-a")}
				if order == "dependency first" {
					_, err = gate.Exec(ctx, insert, args...)
					require.NoError(t, err)
					wait := h.ExpectBackendError("sql: no rows in result set")
					request := lc1Request(t, ctx, h, &requests, lc1Delete(h, kind+"-a"))
					lc1BlockedBy(t, ctx, observer, int(writer.PgConn().PID()))
					t.Log("observed DeleteAll waiting for the fixture writer's FK lock")
					require.NoError(t, gate.Commit(ctx))
					result := <-request
					require.NoError(t, result.err)
					require.Equal(t, http.StatusOK, result.status)
					require.Len(t, result.response.Errors, 1)
					wait()
					after := stepOrganizationSnapshot(t, h)
					lc1Evidence(t, h, before, after, &result.response)
					for table := range before {
						if table != "escalation_policy_actions" {
							require.Equal(t, before[table], after[table], "only the fixture writer's committed Action may change")
						}
					}
					var count int
					require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM escalation_policy_actions WHERE id IN ($1,$2)`, h.UUID("lc1-action"), h.UUID("lc1-concurrent-action")).Scan(&count))
					require.Equal(t, 2, count, "the old and concurrently committed Actions must both survive")
				} else {
					_, err = gate.Exec(ctx, `SELECT id FROM escalation_policies WHERE id=$1 FOR UPDATE`, h.UUID("policy-a"))
					require.NoError(t, err)
					request := lc1Request(t, ctx, h, &requests, lc1Delete(h, kind+"-a"))
					deletePID := lc1BlockedBy(t, ctx, observer, int(writer.PgConn().PID()))
					// The deletion must already protect both reparentable links
					// while it waits to lock the owning Policy.
					for _, target := range []struct{ table, id string }{{"escalation_policy_actions", "lc1-action"}, {"escalation_policy_steps", "step-a1"}} {
						_, err = observer.Exec(ctx, `SELECT id FROM `+target.table+` WHERE id=$1 FOR UPDATE NOWAIT`, h.UUID(target.id))
						var pgErr *pgconn.PgError
						require.ErrorAs(t, err, &pgErr)
						require.Equal(t, "55P03", pgErr.Code, "Action/Step reparenting must be fenced until deletion ends")
						t.Logf("observed %s lock fencing, SQLSTATE %s", target.table, pgErr.Code)
					}
					inserter := lc1Connection(t, ctx, h)
					inserted := make(chan error, 1)
					requests.Add(1)
					go func() {
						defer requests.Done()
						_, insertErr := inserter.Exec(ctx, insert, args...)
						inserted <- insertErr
					}()
					require.Equal(t, int(inserter.PgConn().PID()), lc1BlockedBy(t, ctx, observer, deletePID))
					t.Log("observed the late fixture Action insert waiting for DeleteAll's root lock")
					require.NoError(t, gate.Rollback(ctx))
					result := <-request
					require.NoError(t, result.err)
					require.Equal(t, http.StatusOK, result.status)
					require.Empty(t, result.response.Errors)
					var pgErr *pgconn.PgError
					require.ErrorAs(t, <-inserted, &pgErr)
					require.Equal(t, "23503", pgErr.Code, "late Action insert must fail its real FK after the root commits deletion")
					t.Logf("late Action insert rejected after root deletion, SQLSTATE %s", pgErr.Code)
					after := stepOrganizationSnapshot(t, h)
					lc1Evidence(t, h, before, after, &result.response)
					require.Equal(t, before["escalation_policies"], after["escalation_policies"])
					require.Equal(t, before["escalation_policy_steps"], after["escalation_policy_steps"])
					var count int
					require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM escalation_policy_actions WHERE id IN ($1,$2)`, h.UUID("lc1-action"), h.UUID("lc1-concurrent-action")).Scan(&count))
					require.Zero(t, count)
				}
			})
		}
	}
}
