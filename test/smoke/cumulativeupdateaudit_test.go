package smoke

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/app"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/auth/authtoken"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/schedule/rotation"
	"github.com/target/goalert/service"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/util/log"
)

func cumulativeAuditHarness(t *testing.T) (*harness.Harness, *serviceAuditCapture) {
	t.Helper()
	h := harness.NewStoppedHarness(t, rotationUpdateAuditSQL, nil, "")
	t.Cleanup(h.Close)
	capture := new(serviceAuditCapture)
	h.StartWithAppCfgHook(func(c *app.Config) { c.LegacyLogger.Logrus().AddHook(capture) })
	pauseStepOrganizationEngine(t, h)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	_, err := h.App().DB().Exec(`UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, h.UUID("user-b"))
	require.NoError(t, err)
	var normal int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM organizations o JOIN normal_organizations n ON n.organization_id=o.id WHERE o.id IN($1,$2) AND o.classification='NORMAL'`, harness.SmokeOrganizationID, h.UUID("org-b")).Scan(&normal))
	require.Equal(t, 2, normal)
	return h, capture
}

func cumulativeAuditHTTP(t *testing.T, endpoint, token, query string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"query": query, "extensions": map[string]any{"requestId": "SYNTHETIC_C7_CLIENT_REQUEST", "attemptId": "SYNTHETIC_C7_CLIENT_ATTEMPT"}})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, endpoint+"/api/graphql?trace=1", bytes.NewReader(b))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "44444444-4444-4444-8444-444444444444")
	req.Header.Set("X-Synthetic-Token", "SYNTHETIC_C7_HEADER_TOKEN")
	req.Header.Set("X-Synthetic-SourceInfo", "SYNTHETIC_C7_SOURCEINFO")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	req.AddCookie(&http.Cookie{Name: "SyntheticCookie", Value: "SYNTHETIC_C7_COOKIE"})
	r, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer r.Body.Close()
	b, err = io.ReadAll(r.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.StatusCode)
	return string(b)
}

func cumulativeAuditEvents(t *testing.T, h *harness.Harness) []map[string]any {
	t.Helper()
	var raw string
	require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(e ORDER BY e->>'operation',e->>'outcome'),'[]')::text FROM (
 SELECT to_jsonb(a)||jsonb_build_object('operation','service.update','target_id',service_id) e FROM service_update_audit_events a
 UNION ALL SELECT to_jsonb(a) e FROM schedule_rotation_update_audit_events a) events`).Scan(&raw))
	var rows []map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &rows))
	return rows
}

func cumulativeAuditIdentity(t *testing.T, rows []map[string]any, actor, authority string) {
	t.Helper()
	requests, attempts, events := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, row := range rows {
		for _, field := range []string{"request_id", "attempt_id", "event_id"} {
			id, err := uuid.Parse(row[field].(string))
			require.NoError(t, err)
			require.NotEqual(t, uuid.Nil, id)
		}
		requests[row["request_id"].(string)] = true
		attempts[row["attempt_id"].(string)] = true
		require.False(t, events[row["event_id"].(string)], "every witness is a separate immutable event")
		events[row["event_id"].(string)] = true
		require.Equal(t, "human", row["actor_kind"])
		require.Equal(t, actor, row["actor_id"])
		require.Equal(t, harness.SmokeOrganizationID, row["home_organization_id"])
		require.Equal(t, authority, row["authority_role"])
		require.Equal(t, "current_local_user_organization_at_admission", row["authority_source"])
	}
	require.Len(t, requests, 1, "server request correlation spans separate business transactions")
	require.False(t, requests["44444444-4444-4444-8444-444444444444"], "client header cannot choose the trusted RequestID")
	require.Len(t, attempts, 3, "three roots must have independent AttemptIDs")
}

func cumulativeAuditEvidence(t *testing.T, h *harness.Harness, capture *serviceAuditCapture, token, response string) {
	t.Helper()
	rows := cumulativeAuditEvents(t, h)
	b, err := json.Marshal(rows)
	require.NoError(t, err)
	parsed, _, err := authtoken.Parse(token, nil)
	require.NoError(t, err)
	for _, marker := range []string{token, parsed.ID.String(), "SourceTypeAuthProvider{", "AuthSource=", "SYNTHETIC_C7_", "synthetic.c7.private@example.invalid", "synthetic.c7.public@example.invalid"} {
		for _, output := range []string{response, string(b), capture.String()} {
			require.NotContains(t, output, marker)
		}
	}
	if dir := os.Getenv("CUMULATIVE_AUDIT_EVIDENCE"); dir != "" {
		var database, version string
		require.NoError(t, h.App().DB().QueryRow(`SELECT current_database(),current_setting('server_version')`).Scan(&database, &version))
		b, err := json.MarshalIndent(map[string]any{"database": database, "postgres_version": version, "http_status": http.StatusOK, "response": json.RawMessage(response), "events": rows, "logs": capture.String(), "business": serviceManagementSnapshot(t, h)}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "-")+".json"), append(b, '\n'), 0600))
	}
}

func TestD09C7MixedRootTransactionsAndAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, user, authority, service, schedule, rotation string
		committed                                          int
	}{
		{"PlatformAdmin", "user-a", "platform_admin", "service-b", "schedule-control", "rotation-b", 2},
		{"OrgAdmin", "user-b", "org_admin", "service-a", "schedule-control", "rotation-b", 2},
		{"OrgMember", "user-c", "org_member", "service-a", "schedule-control", "rotation-a", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, capture := cumulativeAuditHarness(t)
			token := h.GraphQLToken(h.UUID(tc.user))
			before := serviceManagementSnapshot(t, h)
			// Each alias deliberately names a different real mutation. Fragment
			// expansion must preserve independent roots and schema-field policy.
			response := cumulativeAuditHTTP(t, h.URL(), token, fmt.Sprintf(`mutation Mixed{...Roots} fragment Roots on Mutation{
 updateRotation:updateService(input:{id:%q,description:"SYNTHETIC_C7_SERVICE"})
 updateService:updateSchedule(input:{id:%q,description:"SYNTHETIC_C7_SCHEDULE"})
 updateSchedule:updateRotation(input:{id:%q,description:"SYNTHETIC_C7_ROTATION"})}`, h.UUID(tc.service), h.UUID(tc.schedule), h.UUID(tc.rotation)))
			require.Contains(t, response, `"errors"`)
			require.Contains(t, response, `"data":null`, "non-null GraphQL bubbling does not roll back earlier successful root transactions")
			rows := cumulativeAuditEvents(t, h)
			require.Len(t, rows, 3)
			cumulativeAuditIdentity(t, rows, h.UUID(tc.user), tc.authority)
			committed := 0
			for _, row := range rows {
				if row["outcome"] == "committed" {
					committed++
					wantOrg := harness.SmokeOrganizationID
					if tc.name == "PlatformAdmin" && row["operation"] == "service.update" {
						wantOrg = h.UUID("org-b")
					}
					require.Equal(t, wantOrg, row["target_organization_id"])
				} else {
					require.Nil(t, row["target_id"])
					require.Nil(t, row["target_organization_id"], "unavailable target cannot be invented from Home or client ID")
				}
			}
			require.Equal(t, tc.committed, committed)
			for _, row := range rows {
				require.EqualValues(t, 2, row["requested_fields"])
				if row["outcome"] != "committed" {
					if tc.committed == 0 {
						require.Equal(t, "denied", row["outcome"])
						require.Equal(t, "authority_denied", row["reason_code"])
					} else {
						require.Equal(t, "validation_failed", row["outcome"])
						require.Equal(t, "target_unavailable", row["reason_code"])
					}
				}
			}
			after := serviceManagementSnapshot(t, h)
			for _, table := range []string{"rotations", "rotation_participants", "rotation_state", "users", "user_organization_assignments"} {
				require.Contains(t, before, table)
				require.Equal(t, before[table], after[table], table)
			}
			for _, item := range []struct{ table, id, value string }{{"services", tc.service, "SYNTHETIC_C7_SERVICE"}, {"schedules", tc.schedule, "SYNTHETIC_C7_SCHEDULE"}} {
				var actual string
				require.NoError(t, h.App().DB().QueryRow(`SELECT description FROM `+item.table+` WHERE id=$1`, h.UUID(item.id)).Scan(&actual))
				if tc.committed > 0 {
					require.Equal(t, item.value, actual)
				} else {
					require.Empty(t, actual)
				}
			}
			cumulativeAuditEvidence(t, h, capture, token, response)
		})
	}
}

// This seam changes only Commit acknowledgement around a real PG transaction.
// It is neither a network-disconnect experiment nor a rollback inference.
type cumulativeAckConnector struct {
	base     driver.Connector
	rollback bool
	injected atomic.Int64
}

func (c *cumulativeAckConnector) Driver() driver.Driver { return c.base.Driver() }
func (c *cumulativeAckConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &cumulativeAckConn{serviceAuditFaultConn: serviceAuditFaultConn{Conn: conn}, connector: c}, nil
}

type cumulativeAckConn struct {
	serviceAuditFaultConn
	connector *cumulativeAckConnector
	current   *cumulativeAckTx
}

func (c *cumulativeAckConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	c.current = &cumulativeAckTx{Tx: tx, connector: c.connector}
	return c.current, nil
}

func (c *cumulativeAckConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	r, err := c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
	if err == nil && strings.HasPrefix(q, "INSERT INTO schedule_rotation_update_audit_events (") && len(args) > 15 && args[4].Value == "rotation.update" && args[15].Value == "committed" {
		c.current.inject = true
	}
	return r, err
}

type cumulativeAckTx struct {
	driver.Tx
	connector *cumulativeAckConnector
	inject    bool
}

func (tx *cumulativeAckTx) Commit() error {
	if !tx.inject {
		return tx.Tx.Commit()
	}
	var err error
	if tx.connector.rollback {
		err = tx.Rollback()
	} else {
		err = tx.Tx.Commit()
	}
	if err != nil {
		return err
	}
	tx.connector.injected.Add(1)
	return errors.New("SYNTHETIC_C7_COMMIT_ACK")
}

func TestD09C7MixedRootUnknownIsolation(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(fmt.Sprintf("native_rollback_%t", rollback), func(t *testing.T) {
			h, capture := cumulativeAuditHarness(t)
			var database string
			require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&database))
			cfg, err := pgx.ParseConfig(harness.DBURL(database))
			require.NoError(t, err)
			connector := &cumulativeAckConnector{base: stdlib.GetConnector(*cfg), rollback: rollback}
			db := sql.OpenDB(connector)
			defer db.Close()
			backend := h.App()
			serviceStore, err := service.NewStore(context.Background(), db)
			require.NoError(t, err)
			scheduleStore, err := schedule.NewStore(context.Background(), db, nil)
			require.NoError(t, err)
			rotationStore, err := rotation.NewStore(context.Background(), db)
			require.NoError(t, err)
			a := graphqlapp.App{DB: db, ServiceStore: serviceStore, ScheduleStore: scheduleStore, RotationStore: rotationStore,
				AlertStore: backend.AlertStore, PolicyStore: backend.EscalationStore, UserStore: backend.UserStore, CMStore: backend.ContactMethodStore,
				HeartbeatStore: backend.HeartbeatStore, NotificationStore: backend.NotificationStore, NCStore: backend.NCStore, AlertMetricsStore: backend.AlertMetricsStore}
			ec, err := executioncontext.NewHumanExecutionContextConstructor(backend.OrganizationStore)
			require.NoError(t, err)
			// Use the actual signed-session authenticator and current authority
			// constructor, in production order. No synthetic auth context is used.
			handler := backend.AuthHandler.WrapHandler(ec.WrapHandler(a.Handler()))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handler.ServeHTTP(w, r.WithContext(log.SetRequestID(backend.Context(r.Context()))))
			}))
			defer server.Close()
			require.Contains(t, server.URL, "127.0.0.1:")
			waitRotation := h.ExpectBackendError("rotation.update transaction failed")
			token := h.GraphQLToken(h.UUID("user-a"))
			// The rejected middle root must not prevent the third transaction.
			_, err = h.App().DB().Exec(`INSERT INTO schedules(id,organization_id,name,time_zone) VALUES($1,$2,'Foreign schedule','Etc/UTC')`, h.UUID("c7-foreign-schedule"), h.UUID("org-b"))
			require.NoError(t, err)
			response := cumulativeAuditHTTP(t, server.URL, token, fmt.Sprintf(`mutation{
 s:updateService(input:{id:%q,description:"SYNTHETIC_C7_SUCCESS"})
 f:updateSchedule(input:{id:%q,description:"SYNTHETIC_C7_DENIED"})
 u:updateRotation(input:{id:%q,description:"SYNTHETIC_C7_UNKNOWN"})}`, h.UUID("service-b"), h.UUID("c7-foreign-schedule"), h.UUID("rotation-a")))
			waitRotation()
			require.EqualValues(t, 1, connector.injected.Load(), "one native rotation finalization, no mutation replay")
			var body struct{ Errors []struct{ Path []string } }
			require.NoError(t, json.Unmarshal([]byte(response), &body))
			require.Len(t, body.Errors, 2)
			require.Equal(t, []string{"f"}, body.Errors[0].Path)
			require.Equal(t, []string{"u"}, body.Errors[1].Path)
			rows := cumulativeAuditEvents(t, h)
			cumulativeAuditIdentity(t, rows, h.UUID("user-a"), "platform_admin")
			outcomes := map[string]int{}
			attempt := ""
			for _, row := range rows {
				outcomes[row["operation"].(string)+"/"+row["outcome"].(string)]++
				if row["operation"] == "rotation.update" {
					if attempt != "" {
						require.Equal(t, attempt, row["attempt_id"], "uncertainty appends beside the committed witness of the same attempt")
					}
					attempt = row["attempt_id"].(string)
					require.Equal(t, harness.SmokeOrganizationID, row["target_organization_id"])
					require.Equal(t, h.UUID("rotation-a"), row["target_id"])
					if row["outcome"] == "commit_unknown" {
						require.Equal(t, "commit_unconfirmed", row["reason_code"])
						require.Equal(t, false, row["rotation_row_written"])
					}
				}
			}
			require.Equal(t, 1, outcomes["service.update/committed"])
			require.Equal(t, 1, outcomes["schedule.update/validation_failed"])
			require.Equal(t, 1, outcomes["rotation.update/commit_unknown"])
			var serviceDescription, scheduleDescription, rotationDescription string
			require.NoError(t, h.App().DB().QueryRow(`SELECT description FROM services WHERE id=$1`, h.UUID("service-b")).Scan(&serviceDescription))
			require.NoError(t, h.App().DB().QueryRow(`SELECT description FROM schedules WHERE id=$1`, h.UUID("c7-foreign-schedule")).Scan(&scheduleDescription))
			require.NoError(t, h.App().DB().QueryRow(`SELECT description FROM rotations WHERE id=$1`, h.UUID("rotation-a")).Scan(&rotationDescription))
			require.Equal(t, "SYNTHETIC_C7_SUCCESS", serviceDescription)
			require.Empty(t, scheduleDescription)
			if rollback {
				require.Len(t, rows, 3)
				require.Zero(t, outcomes["rotation.update/committed"])
				require.Empty(t, rotationDescription)
			} else {
				require.Len(t, rows, 4)
				require.Equal(t, 1, outcomes["rotation.update/committed"])
				require.Equal(t, "SYNTHETIC_C7_UNKNOWN", rotationDescription)
			}
			cumulativeAuditEvidence(t, h, capture, token, response)
		})
	}
}

func TestD09C7CrossRootPrivacy(t *testing.T) {
	h, capture := cumulativeAuditHarness(t)
	for _, private := range []bool{true, false} {
		value := "synthetic.c7.public@example.invalid"
		if private {
			value = "synthetic.c7.private@example.invalid"
		}
		_, err := h.App().DB().Exec(`INSERT INTO user_contact_methods(id,user_id,name,type,value,private) VALUES($1,$2,'Synthetic privacy','EMAIL',$3,$4)`, uuid.NewString(), h.UUID("user-a"), value, private)
		require.NoError(t, err)
	}
	token := h.GraphQLToken(h.UUID("user-a"))
	query := fmt.Sprintf(`mutation Privacy{...Mixed} fragment Mixed on Mutation{
 updateRotation:updateService(input:{id:%q,name:"SYNTHETIC_C7_SERVICE_NAME",description:"SYNTHETIC_C7_SERVICE_DESCRIPTION"})
 updateService:updateSchedule(input:{id:%q,name:"SYNTHETIC_C7_SCHEDULE_NAME",description:"SYNTHETIC_C7_SCHEDULE_DESCRIPTION"})
 updateSchedule:updateRotation(input:{id:%q,name:"SYNTHETIC_C7_ROTATION_NAME",description:"SYNTHETIC_C7_ROTATION_DESCRIPTION"})}`, h.UUID("service-b"), h.UUID("schedule-control"), h.UUID("rotation-a"))
	response := cumulativeAuditHTTP(t, h.URL(), token, query)
	require.NotContains(t, response, `"errors"`)
	for _, name := range []string{"updateService", "updateSchedule", "updateRotation"} {
		require.Contains(t, capture.String(), `"MutationName":"`+name+`","MutationResult":"success"`)
	}
	cumulativeAuditIdentity(t, cumulativeAuditEvents(t, h), h.UUID("user-a"), "platform_admin")
	cumulativeAuditEvidence(t, h, capture, token, response)
	_, err := h.App().DB().Exec(`CREATE FUNCTION c7_private_sql_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING MESSAGE='SYNTHETIC_C7_SQL_MESSAGE',DETAIL='SYNTHETIC_C7_SQL_DETAIL'; END $$;
 CREATE TRIGGER c7_private_sql_failure BEFORE UPDATE ON services FOR EACH ROW EXECUTE FUNCTION c7_private_sql_failure();
 CREATE TRIGGER c7_private_sql_failure BEFORE UPDATE ON schedules FOR EACH ROW EXECUTE FUNCTION c7_private_sql_failure();
 CREATE TRIGGER c7_private_sql_failure BEFORE UPDATE ON rotations FOR EACH ROW EXECUTE FUNCTION c7_private_sql_failure()`)
	require.NoError(t, err)
	before := serviceManagementSnapshot(t, h)
	waits := []func(){h.ExpectBackendError("service.update transaction failed"), h.ExpectBackendError("schedule.update transaction failed"), h.ExpectBackendError("rotation.update transaction failed")}
	failure := cumulativeAuditHTTP(t, h.URL(), token, query)
	for _, wait := range waits {
		wait()
	}
	var body struct{ Errors []json.RawMessage }
	require.NoError(t, json.Unmarshal([]byte(failure), &body))
	require.Len(t, body.Errors, 3)
	require.Equal(t, before, serviceManagementSnapshot(t, h))
	rows := cumulativeAuditEvents(t, h)
	require.Len(t, rows, 6)
	for _, operation := range []string{"service.update", "schedule.update", "rotation.update"} {
		count := 0
		for _, row := range rows {
			if row["operation"] == operation && row["outcome"] == "tx_failed" {
				count++
			}
		}
		require.Equal(t, 1, count, operation)
	}
	// Evidence from both requests is retained; the first oracle already checked
	// all successful logs and HTTP output before the SQL-failure request.
	t.Run("SQLFailure", func(t *testing.T) { cumulativeAuditEvidence(t, h, capture, token, failure) })
}
