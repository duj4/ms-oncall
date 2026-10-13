package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/alert"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func ack01Harness(t *testing.T) *harness.Harness {
	t.Helper()
	h := alertOrganizationHarness(t)
	exec := func(query string, args ...any) {
		t.Helper()
		_, err := h.App().DB().Exec(query, args...)
		require.NoError(t, err)
	}
	exec(`UPDATE escalation_policy_steps SET multi_ack=true WHERE id=$1`, h.UUID("step-a"))
	exec(`INSERT INTO escalation_policy_steps(id,escalation_policy_id,delay,step_number,multi_ack)
		VALUES($1,$2,1,1,false)`, h.UUID("step-false"), h.UUID("policy-a"))
	exec(`INSERT INTO alerts(id,service_id,summary,status,dedup_key) VALUES
		(31,$1,'live true','active','auto:1:ack01-31'),(32,$1,'live false','active','auto:1:ack01-32'),
		(33,$1,'no state','active','auto:1:ack01-33'),(34,$1,'no live step','active','auto:1:ack01-34'),(36,$1,'first false','triggered','auto:1:ack01-36')`, h.UUID("service-a"))
	// Alert insertion seeds EP state through a database trigger; replace only these test-owned states.
	exec(`DELETE FROM escalation_policy_state WHERE alert_id IN (11,21,31,32,33,34,36)`)
	exec(`INSERT INTO escalation_policy_state(alert_id,escalation_policy_id,escalation_policy_step_id)
		VALUES(11,$1,$2),(31,$1,$2),(32,$1,$3),(34,$1,NULL),(36,$1,$3)`, h.UUID("policy-a"), h.UUID("step-a"), h.UUID("step-false"))
	exec(`UPDATE alerts SET status='active' WHERE id=21`)
	exec(`UPDATE escalation_policy_steps SET multi_ack=true WHERE id=$1`, h.UUID("step-b"))
	exec(`INSERT INTO escalation_policy_state(alert_id,escalation_policy_id,escalation_policy_step_id)
		VALUES(21,$1,$2)`, h.UUID("policy-b"), h.UUID("step-b"))
	return h
}

func ack01Human(t *testing.T, h *harness.Harness, user string) context.Context {
	t.Helper()
	id, session := h.UUID(user), uuid.NewString()
	var role permission.Role
	require.NoError(t, h.App().DB().QueryRow(`SELECT role FROM users WHERE id=$1`, id).Scan(&role))
	ctx := permission.UserSourceContext(h.Config().Context(t.Context()), id, role,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session})
	r, err := auth.NewRequester(id, session)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, r)
	c, err := executioncontext.NewHumanExecutionContextConstructor(h.App().OrganizationStore)
	require.NoError(t, err)
	authority, err := c.Construct(ctx)
	require.NoError(t, err)
	return executioncontext.WithExecutionContext(ctx, authority)
}

func ack01GraphQL(t *testing.T, h *harness.Harness, user, ids, status string, want ...int) {
	t.Helper()
	response := stepOrganizationPost(t, h, map[string]any{"query": fmt.Sprintf(
		`mutation{updateAlerts(input:{alertIDs:[%s],newStatus:%s}){alertID}}`, ids, status)}, h.GraphQLToken(h.UUID(user)), false)
	require.Empty(t, response.Errors)
	var data struct{ UpdateAlerts []struct{ AlertID int } }
	require.NoError(t, json.Unmarshal(response.Data, &data))
	got := make([]int, 0, len(data.UpdateAlerts))
	for _, a := range data.UpdateAlerts {
		got = append(got, a.AlertID)
	}
	require.ElementsMatch(t, want, got)
	t.Logf("authenticated GraphQL actor=%s returned=%v", h.UUID(user), got)
}

func TestACK01GraphQLActorsAndRetry(t *testing.T) {
	h := ack01Harness(t)
	for i, user := range []string{"user-a", "admin-a", "user-a"} {
		ack01GraphQL(t, h, user, "11,11", "StatusAcknowledged", 11)
		multiAckStatus(t, h, 11, "active")
		want := []string{h.UUID("user-a")}
		if i > 0 {
			want = append(want, h.UUID("admin-a"))
		}
		if i > 1 {
			want = append(want, h.UUID("user-a"))
		}
		multiAckLogUsers(t, h, 11, want...)
	}
	var count, distinct int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*),count(DISTINCT sub_user_id)
		FROM alert_logs WHERE alert_id=11 AND event='acknowledged'`).Scan(&count, &distinct))
	require.Equal(t, 3, count)
	require.Equal(t, 2, distinct)
	var actors string
	require.NoError(t, h.App().DB().QueryRow(`SELECT jsonb_agg(sub_user_id ORDER BY id)::text
		FROM alert_logs WHERE alert_id=11 AND event='acknowledged'`).Scan(&actors))
	t.Logf("persisted ordered ACK sub_user_id=%s", actors)
	t.Logf("ACK events=%d distinct actors=%d; first ACK and duplicate input each contribute one event", count, distinct)
}

func TestACK01EligibilityAndCompatibility(t *testing.T) {
	h := ack01Harness(t)
	org := uuid.MustParse(harness.SmokeOrganizationID)
	human := ack01Human(t, h, "user-a")
	before := alertOrganizationSnapshot(t, h)
	for _, tc := range []struct {
		ctx context.Context
		org *uuid.UUID
	}{
		{human, nil},
		{permission.SystemContext(human, "ACK01"), &org},
		{permission.UserContext(h.Config().Context(t.Context()), h.UUID("user-a"), permission.RoleUser), &org},
		{permission.UserSourceContext(h.Config().Context(t.Context()), h.UUID("user-a"), permission.RoleUser,
			&permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey}), &org},
	} {
		ids, err := h.App().AlertStore.UpdateManyAlertStatusScoped(tc.ctx, alert.StatusActive, []int{31}, nil, tc.org)
		require.NoError(t, err)
		require.Empty(t, ids)
		require.Equal(t, before, alertOrganizationSnapshot(t, h))
	}
	// Operation denial wins over invalid length/status and leaves every row intact.
	ids, err := h.App().AlertStore.UpdateManyAlertStatusScoped(context.Background(), alert.StatusTriggered, make([]int, 501), nil, &org)
	require.True(t, permission.IsPermissionError(err))
	require.Empty(t, ids)
	require.Equal(t, before, alertOrganizationSnapshot(t, h))
	// Missing and inconsistent human authority are rejected before Store effects.
	status := graphql2.AlertStatusStatusAcknowledged
	for _, ctx := range []context.Context{
		permission.UserSourceContext(t.Context(), h.UUID("user-a"), permission.RoleUser, permission.Source(human)),
		permission.SourceContext(human, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}),
	} {
		_, err := alertOrganizationApp(h).Mutation().UpdateAlerts(ctx, graphql2.UpdateAlertsInput{AlertIDs: []int{31}, NewStatus: &status})
		require.True(t, permission.IsPermissionError(err))
		require.Equal(t, before, alertOrganizationSnapshot(t, h))
	}
	_, err = h.App().AlertStore.UpdateManyAlertStatusScoped(human, alert.StatusActive, make([]int, 501), nil, &org)
	require.Error(t, err, "original input length must be checked before deduplication")
	ids, err = h.App().AlertStore.UpdateManyAlertStatusScoped(human, alert.StatusActive, nil, nil, &org)
	require.NoError(t, err)
	require.Empty(t, ids)
	ack01GraphQL(t, h, "user-a", "21,999", "StatusAcknowledged")
	require.Equal(t, before, alertOrganizationSnapshot(t, h))
	ack01GraphQL(t, h, "user-a", "11,11,31,31,32,33,34,13,36,21,999", "StatusAcknowledged", 11, 31, 36)
	for _, id := range []int{11, 31, 36} {
		multiAckLogUsers(t, h, id, h.UUID("user-a"))
		multiAckStatus(t, h, id, "active")
	}
	for _, tc := range []struct {
		id    int
		state string
	}{{32, "active"}, {33, "active"}, {34, "active"}, {13, "closed"}, {21, "active"}} {
		multiAckLogUsers(t, h, tc.id)
		var state string
		require.NoError(t, h.App().DB().QueryRow(`SELECT status FROM alerts WHERE id=$1`, tc.id).Scan(&state))
		require.Equal(t, tc.state, state)
	}
	ack01GraphQL(t, h, "user-a", "11,31,32,33,34,13,36,21,999", "StatusClosed", 11, 31, 32, 33, 34, 36)
	for _, id := range []int{11, 31, 32, 33, 34, 36} {
		multiAckStatus(t, h, id, "closed")
		var count int
		require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM alert_logs WHERE alert_id=$1 AND event='closed' AND sub_user_id=$2`, id, h.UUID("user-a")).Scan(&count))
		require.Equal(t, 1, count)
	}
	before = alertOrganizationSnapshot(t, h)
	ack01GraphQL(t, h, "admin-a", "11,31,32,13,36", "StatusAcknowledged")
	ack01GraphQL(t, h, "admin-a", "11,31", "StatusClosed")
	require.Equal(t, before, alertOrganizationSnapshot(t, h))
}

func TestACK01LogFailureRollsBackBatch(t *testing.T) {
	h := ack01Harness(t)
	// Reject the supplemental ACK; the other row in the same batch advances.
	_, err := h.App().DB().Exec(`CREATE FUNCTION ack01_reject_log() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.alert_id=31 AND NEW.event='acknowledged' THEN RAISE EXCEPTION 'ACK01 log failure'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER ack01_reject_log BEFORE INSERT ON alert_logs FOR EACH ROW EXECUTE FUNCTION ack01_reject_log()`)
	require.NoError(t, err)
	before := alertOrganizationSnapshot(t, h)
	org := uuid.MustParse(harness.SmokeOrganizationID)
	ids, err := h.App().AlertStore.UpdateManyAlertStatusScoped(ack01Human(t, h, "user-a"), alert.StatusActive, []int{11, 31}, map[string]string{"check": "ACK01"}, &org)
	require.ErrorContains(t, err, "ACK01 log failure")
	require.Empty(t, ids)
	require.Equal(t, before, alertOrganizationSnapshot(t, h), "both state advancement and all logs must roll back")
	_, err = h.App().DB().Exec(`DROP TRIGGER ack01_reject_log ON alert_logs; DROP FUNCTION ack01_reject_log()`)
	require.NoError(t, err)
	ids, err = h.App().AlertStore.UpdateManyAlertStatusScoped(ack01Human(t, h, "user-a"), alert.StatusActive, []int{11, 31}, map[string]string{"check": "ACK01"}, &org)
	require.NoError(t, err)
	require.ElementsMatch(t, []int{11, 31}, ids)
	var count int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM alert_logs WHERE alert_id IN (11,31)
		AND event='acknowledged' AND sub_user_id=$1 AND meta->>'check'='ACK01'`, h.UUID("user-a")).Scan(&count))
	require.Equal(t, 2, count)
	t.Log("injected necessary log failure: exact durable snapshot restored; subsequent batch wrote two correct Actor/meta logs")
}

type ack01Trace struct {
	before, after func(context.Context, *pgx.Conn)
}
type ack01TraceKey struct{}

func (tr *ack01Trace) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	lock := strings.Contains(d.SQL, "-- name: Alert_LockManyAlertServices")
	if lock && tr.before != nil {
		tr.before(ctx, c)
	}
	return context.WithValue(ctx, ack01TraceKey{}, lock)
}
func (tr *ack01Trace) TraceQueryEnd(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryEndData) {
	lock, _ := ctx.Value(ack01TraceKey{}).(bool)
	if lock && d.Err == nil && tr.after != nil {
		tr.after(ctx, c)
	}
}

func ack01Traced(t *testing.T, h *harness.Harness, tr *ack01Trace) *alert.Store {
	t.Helper()
	var name string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&name))
	cfg, err := pgx.ParseConfig(harness.DBURL(name))
	require.NoError(t, err)
	cfg.Tracer = tr
	db := sql.OpenDB(stdlib.GetConnector(*cfg))
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	s, err := alert.NewStore(t.Context(), db, h.App().AlertLogStore)
	require.NoError(t, err)
	return s
}

func TestACK01BoundedOrdering(t *testing.T) {
	for _, tc := range []struct {
		name          string
		first, second alert.Status
		acks, closes  int
		secondOK      bool
	}{
		{"ACK ACK", alert.StatusActive, alert.StatusActive, 2, 0, true},
		{"ACK Close", alert.StatusActive, alert.StatusClosed, 1, 1, true},
		{"Close ACK", alert.StatusClosed, alert.StatusActive, 0, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := ack01Harness(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			firstPID, secondPID := make(chan int, 1), make(chan int, 1)
			release := make(chan struct{})
			first := ack01Traced(t, h, &ack01Trace{after: func(ctx context.Context, c *pgx.Conn) {
				firstPID <- int(c.PgConn().PID())
				select {
				case <-release:
				case <-ctx.Done():
				}
			}})
			second := ack01Traced(t, h, &ack01Trace{before: func(_ context.Context, c *pgx.Conn) { secondPID <- int(c.PgConn().PID()) }})
			org := uuid.MustParse(harness.SmokeOrganizationID)
			type result struct {
				ids []int
				err error
			}
			run := func(s *alert.Store, user string, status alert.Status) <-chan result {
				ch := make(chan result, 1)
				deadline, _ := ctx.Deadline()
				human, cancel := context.WithDeadline(ack01Human(t, h, user), deadline)
				go func() {
					defer cancel()
					ids, err := s.UpdateManyAlertStatusScoped(human, status, []int{31}, nil, &org)
					ch <- result{ids, err}
				}()
				return ch
			}
			receivePID := func(ch <-chan int) int {
				select {
				case pid := <-ch:
					return pid
				case <-ctx.Done():
					t.Fatal("lock synchronization deadline")
					return 0
				}
			}
			a := run(first, "user-a", tc.first)
			blocker := receivePID(firstPID)
			b := run(second, "admin-a", tc.second)
			waiter := receivePID(secondPID)
			scheduleDataWaitBlocked(t, ctx, h.App().DB(), waiter, blocker)
			close(release)
			receive := func(ch <-chan result) result {
				select {
				case r := <-ch:
					return r
				case <-ctx.Done():
					t.Fatal("batch deadline")
					return result{}
				}
			}
			ra, rb := receive(a), receive(b)
			require.NoError(t, ra.err)
			require.NoError(t, rb.err)
			require.Equal(t, []int{31}, ra.ids)
			if tc.secondOK {
				require.Equal(t, []int{31}, rb.ids)
			} else {
				require.Empty(t, rb.ids)
			}
			var acks, closes int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FILTER(WHERE event='acknowledged'),count(*) FILTER(WHERE event='closed') FROM alert_logs WHERE alert_id=31`).Scan(&acks, &closes))
			require.Equal(t, tc.acks, acks)
			require.Equal(t, tc.closes, closes)
			actors := []string{}
			if tc.acks > 0 {
				actors = append(actors, h.UUID("user-a"))
			}
			if tc.acks > 1 {
				actors = append(actors, h.UUID("admin-a"))
			}
			multiAckLogUsers(t, h, 31, actors...)
			state := "active"
			if tc.closes > 0 {
				state = "closed"
			}
			multiAckStatus(t, h, 31, state)
			t.Logf("database-observed waiter=%d blocked by=%d; successful IDs=%v/%v; ACK=%d Close=%d", waiter, blocker, ra.ids, rb.ids, acks, closes)
		})
	}
}
