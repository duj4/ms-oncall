package graphqlapp

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/schedule/rule"
	"github.com/target/goalert/util/log"
)

// Only the database transport is controlled. Requests go through App.Handler:
// POST decoding, gqlgen parsing/fragment collection, real resolvers, the real
// error presenter and the request's real JSON logger. No PostgreSQL is used.
type updateHTTPConnector struct {
	failWrite bool
	model     *u03Model
	failBegin int
	begins    int
	faults    int
	failure   error
}

func (c *updateHTTPConnector) Connect(context.Context) (driver.Conn, error) {
	return &updateHTTPConn{u03ModelConn: &u03ModelConn{m: c.model}, fixture: c}, nil
}
func (*updateHTTPConnector) Driver() driver.Driver { return sd2Driver{} }

type updateHTTPConn struct {
	*u03ModelConn
	fixture *updateHTTPConnector
}

func (c *updateHTTPConn) Begin() (driver.Tx, error) {
	c.fixture.begins++
	if c.fixture.begins == c.fixture.failBegin {
		c.fixture.faults++
		return nil, c.fixture.failure
	}
	return c.u03ModelConn.Begin()
}

func (c *updateHTTPConn) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Begin()
	if err == nil {
		c.tx.readOnly = opts.ReadOnly
	}
	return tx, err
}

func (c *updateHTTPConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if c.fixture.failWrite && strings.HasPrefix(compactSQL(q), "insert into schedule_rotation_delete_audit_events") && args[5].Value == "success_witness" {
		c.fixture.faults++
		return nil, c.fixture.failure
	}
	if strings.HasPrefix(compactSQL(q), "insert into escalation_policy_delete_audit_events") {
		return driver.RowsAffected(1), nil
	}
	return c.u03ModelConn.ExecContext(ctx, q, args)
}

func TestUpdateAuditHTTPBackendLogs(t *testing.T) {
	for _, tc := range []struct {
		name       string
		selection  string
		fragment   string
		failBegin  int
		errorCount int
		successes  int
		faults     int
		failWrite  bool
		errorPaths []string
	}{
		{"normal_update", "updateScheduleTarget(input:$schedule)", "", 0, 0, 1, 0, false, nil},
		{"failing_schedule", "updateScheduleTarget(input:$schedule)", "", 1, 1, 0, 1, false, []string{"updateScheduleTarget"}},
		{"failing_policy", "updateEscalationPolicy(input:{id:$id})", "", 1, 1, 0, 1, false, []string{"updateEscalationPolicy"}},
		{"failing_step", "updateEscalationPolicyStep(input:{id:$id})", "", 1, 1, 0, 1, false, []string{"updateEscalationPolicyStep"}},
		{"audit_sql_failure", "updateScheduleTarget(input:$schedule)", "", 0, 1, 0, 1, true, []string{"updateScheduleTarget"}},
		{"mixed_mutation", "ok:updateScheduleTarget(input:$schedule) SYNTHETIC_ALIAS:updateEscalationPolicy(input:{id:$id})", "", 2, 1, 1, 1, false, []string{"SYNTHETIC_ALIAS"}},
		{"alias_fragment_success", "...SYNTHETIC_FRAGMENT", "fragment SYNTHETIC_FRAGMENT on Mutation { SYNTHETIC_ALIAS:updateScheduleTarget(input:$schedule) }", 0, 0, 1, 0, false, nil},
		{"alias_fragment_failure", "...SYNTHETIC_FRAGMENT", "fragment SYNTHETIC_FRAGMENT on Mutation { SYNTHETIC_ALIAS:updateEscalationPolicyStep(input:{id:$id}) }", 1, 1, 0, 1, false, []string{"SYNTHETIC_ALIAS"}},
		// Independent sibling errors retain their own client paths while the
		// backend diagnostics use the enclosing operation's closed projection.
		{"sibling_failure_first", `SYNTHETIC_SIBLING:sendSignal(input:{serviceID:$id,dest:{type:"SYNTHETIC_DESTINATION",args:{}},params:{}}) updateScheduleTarget(input:$schedule)`, "", 0, 1, 1, 0, false, []string{"SYNTHETIC_SIBLING"}},
		{"two_sibling_failures", `SYNTHETIC_SIBLING:sendSignal(input:{serviceID:$id,dest:{type:"SYNTHETIC_DESTINATION",args:{}},params:{}}) SYNTHETIC_ALIAS:updateEscalationPolicy(input:{id:$id})`, "", 1, 2, 0, 1, false, []string{"SYNTHETIC_SIBLING", "SYNTHETIC_ALIAS"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			model, mutation, ctx, target := newU03Model(t, "user", 1)
			// The sentinel error crosses database/sql and the production
			// transaction owner. It includes SQL and destination diagnostics,
			// but is a simulated transport failure, not native SQL evidence.
			pgErr := &pgconn.PgError{
				Code: "XX000", Message: "SYNTHETIC_DESTINATION synthetic@example.invalid",
				Detail: "SYNTHETIC_SQL_DETAIL", Hint: "SYNTHETIC_SQL_HINT",
				Where: "SYNTHETIC_INTERNAL_CONTEXT", InternalQuery: "SELECT SYNTHETIC_SQL",
			}
			fixture := &updateHTTPConnector{model: model, failBegin: tc.failBegin, failWrite: tc.failWrite, failure: pgErr}
			db := sql.OpenDB(fixture)
			db.SetMaxOpenConns(1)
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			app := (*App)(mutation)
			app.DB = db
			var err error
			app.RuleStore, err = rule.NewStore(ctx, db)
			require.NoError(t, err)
			app.ScheduleStore, err = schedule.NewStore(ctx, db, nil)
			require.NoError(t, err)
			var backend bytes.Buffer
			logger := log.NewLogger()
			logger.EnableJSON()
			logger.EnableStacks()
			logger.SetOutput(&backend)
			ctx = log.SetRequestID(log.WithLogger(ctx, logger))
			ctx = log.WithFields(ctx, log.Fields{
				"Authorization": "SYNTHETIC_AUTHORIZATION", "Cookie": "SYNTHETIC_COOKIE",
				"Destination": "SYNTHETIC_DESTINATION", "Path": "SYNTHETIC_PATH",
				"InternalContext": "SYNTHETIC_INTERNAL_CONTEXT",
			})
			declarations := []string{}
			variables := map[string]any{}
			if strings.Contains(tc.selection+tc.fragment, "$schedule") {
				declarations = append(declarations, "$schedule:ScheduleTargetInput!")
				confirmation := u03ModelConfirmation(t, model, ctx, graphql2.ScheduleTargetInput{ScheduleID: &model.schedule, Target: &target})
				variables["schedule"] = map[string]any{"scheduleID": model.schedule, "target": map[string]any{"type": "user", "id": target.ID}, "rules": []any{}, "confirmation": confirmation}
			}
			if strings.Contains(tc.selection+tc.fragment, "$id") {
				declarations = append(declarations, "$id:ID!")
				variables["id"] = uuid.NewString()
			}
			query := fmt.Sprintf("mutation SYNTHETIC_OPERATION(%s) {%s} %s", strings.Join(declarations, ","), tc.selection, tc.fragment)
			body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body)).WithContext(ctx)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer SYNTHETIC_AUTHORIZATION")
			req.Header.Set("Cookie", "SYNTHETIC_COOKIE")
			rec := httptest.NewRecorder()
			app.Handler().ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			var response struct {
				Data   map[string]bool
				Errors []struct {
					Message string
					Path    []string
				}
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
			require.Len(t, response.Errors, tc.errorCount, rec.Body.String())
			require.Equal(t, tc.faults, fixture.faults, "must reach the intended real resolver/transaction owner")
			require.Len(t, model.rules, 1-tc.successes, "only a successful Update removes the Rule")
			if tc.failWrite {
				require.Equal(t, 1, model.deletes)
				require.Equal(t, 1, model.rollbacks, "failed audit write must roll back the deletion")
			}
			require.Zero(t, db.Stats().InUse)
			if tc.errorCount == 0 {
				require.Len(t, response.Data, 1)
				for _, result := range response.Data {
					require.True(t, result)
				}
			} else {
				require.Nil(t, response.Data, "non-null mutation failure nulls the data")
				for i, gqlErr := range response.Errors {
					require.Equal(t, "unexpected error", gqlErr.Message)
					require.Equal(t, []string{tc.errorPaths[i]}, gqlErr.Path)
				}
				for _, sentinel := range []string{"SYNTHETIC_SQL", "SYNTHETIC_DESTINATION", "SYNTHETIC_AUTHORIZATION", "SYNTHETIC_COOKIE", "SYNTHETIC_INTERNAL_CONTEXT", "SYNTHETIC_PATH", "synthetic@example.invalid"} {
					require.NotContains(t, rec.Body.String(), sentinel)
				}
			}
			lines := strings.Split(strings.TrimSpace(backend.String()), "\n")
			require.Len(t, lines, tc.successes+tc.errorCount, "capture actual success/error logs")
			successes, failures := 0, 0
			for _, line := range lines {
				var entry map[string]any
				require.NoError(t, json.Unmarshal([]byte(line), &entry))
				require.Equal(t, "graphql_closed_projection", entry["DiagnosticPolicy"])
				require.Equal(t, log.RequestID(ctx), entry["RequestID"])
				switch entry["level"] {
				case "info":
					successes++
					require.Equal(t, "Mutation.", entry["msg"])
					require.Equal(t, "updateScheduleTarget", entry["MutationName"])
					require.NotContains(t, entry, "error")
				case "error":
					failures++
					require.Equal(t, "GraphQL operation failed", entry["error"])
					require.NotContains(t, entry, "MutationName", "do not borrow a successful sibling's diagnostics")
				default:
					t.Fatalf("unexpected backend log level: %v", entry["level"])
				}
			}
			require.Equal(t, tc.successes, successes)
			require.Equal(t, tc.errorCount, failures)
			for _, sentinel := range []string{"SYNTHETIC_", "synthetic@example.invalid", "Bearer", "XX000", "SELECT", model.schedule, target.ID} {
				require.NotContains(t, backend.String(), sentinel)
			}
			if tc.name == "sibling_failure_first" {
				require.Equal(t, []string{"SYNTHETIC_SIBLING"}, response.Errors[0].Path)
				require.Equal(t, 1, fixture.begins, "the sibling error must not be mistaken for an Update failure")
			}
		})
	}
}
