package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/alert"
	"github.com/target/goalert/alert/alertlog"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/search"
	"github.com/target/goalert/service"
	"github.com/target/goalert/test/smoke/harness"
)

const alertOrganizationSQL = `
INSERT INTO organizations (id, classification, display_name, canonical_name)
VALUES ({{uuid "org-b"}}, 'NORMAL', 'Alert Organization B', 'alert.organization-b');
INSERT INTO normal_organizations (organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
VALUES ({{uuid "org-b"}}, 'NORMAL', 'alert:organization-b', 'Etc/UTC');
INSERT INTO users (id, name, email, role)
VALUES ({{uuid "user-a"}}, 'Alert Organization A User', '', 'user'),
       ({{uuid "admin-a"}}, 'Alert Organization A Admin', '', 'admin');
INSERT INTO escalation_policies (id, organization_id, name)
VALUES ({{uuid "policy-a"}}, {{smokeOrganizationID}}, 'Alert Policy A'),
       ({{uuid "policy-b"}}, {{uuid "org-b"}}, 'Alert Policy B');
INSERT INTO escalation_policy_steps(id, escalation_policy_id, delay, step_number)
VALUES ({{uuid "step-a"}}, {{uuid "policy-a"}}, 1, 0),
       ({{uuid "step-b"}}, {{uuid "policy-b"}}, 1, 0);
INSERT INTO services (id, organization_id, escalation_policy_id, name)
VALUES ({{uuid "service-a"}}, {{smokeOrganizationID}}, {{uuid "policy-a"}}, 'Alert Service A'),
       ({{uuid "service-b"}}, {{uuid "org-b"}}, {{uuid "policy-b"}}, 'Alert Service B');
`

func alertOrganizationHarness(t *testing.T) *harness.Harness {
	t.Helper()
	h := harness.NewHarness(t, alertOrganizationSQL, "")
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	// Create alerts after pausing so Engine time and notifications cannot change observations.
	_, err := h.App().DB().Exec(`
        INSERT INTO alerts(id, service_id, summary, status, dedup_key) VALUES
        (11,$1,'Own matching','triggered','user:1:matching'),
        (12,$1,'Own second','triggered','user:1:second'),
        (13,$1,'Own closed','closed',NULL),
        (21,$2,'Foreign matching','triggered','user:1:matching'),
        (22,$2,'Foreign second','triggered','user:1:second'),
        (23,$2,'Foreign closed','closed',NULL)`, h.UUID("service-a"), h.UUID("service-b"))
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`SELECT setval('alerts_id_seq', 100)`)
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`
        INSERT INTO alert_data(alert_id, metadata) VALUES
        (11,'{"Type":"alert_meta_v1","AlertMetaV1":{"key":"own-value"}}'),
        (21,'{"Type":"alert_meta_v1","AlertMetaV1":{"key":"foreign-value"}}');
        INSERT INTO alert_feedback(alert_id,noise_reason) VALUES (11,'own-noise'),(21,'foreign-noise');
        INSERT INTO alert_logs(alert_id,event,message) VALUES (11,'created','own-log'),(21,'created','foreign-log')`)
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`INSERT INTO alert_metrics(alert_id,service_id,time_to_ack,time_to_close,escalated,closed_at)
        VALUES (13,$1,'1 minute','2 minutes',false,now()),(23,$2,'3 minutes','4 minutes',true,now())`, h.UUID("service-a"), h.UUID("service-b"))
	require.NoError(t, err)
	return h
}

func alertOrganizationApp(h *harness.Harness) *graphqlapp.App {
	a := h.App()
	return &graphqlapp.App{DB: a.DB(), AlertStore: a.AlertStore, AlertLogStore: a.AlertLogStore,
		AlertMetricsStore: a.AlertMetricsStore, ServiceStore: a.ServiceStore}
}

func alertOrganizationSnapshot(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, table := range []string{"alerts", "alert_data", "alert_feedback", "alert_logs", "escalation_policy_state"} {
		var rows string
		require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM `+table+` r`).Scan(&rows))
		result[table] = rows
	}
	return result
}

func alertOrganizationIDs(t *testing.T, response *stepOrganizationResponse) []int {
	t.Helper()
	require.Empty(t, response.Errors)
	var result struct {
		Alerts struct{ Nodes []struct{ AlertID int } }
	}
	require.NoError(t, json.Unmarshal(response.Data, &result))
	ids := make([]int, 0, len(result.Alerts.Nodes))
	for _, a := range result.Alerts.Nodes {
		ids = append(ids, a.AlertID)
	}
	return ids
}

func TestGraphQLAlertOrganizationMaterializationAndCursors(t *testing.T) {
	h := alertOrganizationHarness(t)
	own := stepOrganizationQuery(t, h, `{alert(id:11){alertID summary state{stepNumber} meta{key value} noiseReason recentEvents{nodes{alertID message}}}}`)
	require.Empty(t, own.Errors)
	require.Contains(t, string(own.Data), "own-value")
	require.Contains(t, string(own.Data), "own-noise")
	require.Equal(t, stepOrganizationQuery(t, h, `{alert(id:999){alertID summary}}`), stepOrganizationQuery(t, h, `{alert(id:21){alertID summary}}`))
	require.Equal(t, []int{12, 11, 13}, alertOrganizationIDs(t, stepOrganizationQuery(t, h, `{alerts{nodes{alertID}}}`)))
	for _, forged := range []map[string]any{
		{"OrganizationID": h.UUID("org-b"), "organization_id": h.UUID("org-b"), "organizationID": h.UUID("org-b")},
		{"OrganizationID": nil, "organization_id": nil},
		{"OrganizationID": uuid.Nil.String()},
		{"v": map[string]any{"v": false, "i": []string{h.UUID("service-b")}}, "e": h.UUID("user-a")},
		{"v": map[string]any{"v": true, "i": []string{h.UUID("service-b")}}},
	} {
		cursor, err := search.Cursor(forged)
		require.NoError(t, err)
		ids := alertOrganizationIDs(t, stepOrganizationQuery(t, h, fmt.Sprintf(`{alerts(input:{after:%q}){nodes{alertID}}}`, cursor)))
		for _, id := range ids {
			require.Contains(t, []int{11, 12, 13}, id)
		}
	}
	// Pagination cannot drop scope at a page boundary.
	var after string
	var all []int
	for i := 0; i < 4; i++ {
		response := stepOrganizationQuery(t, h, fmt.Sprintf(`{alerts(input:{first:1,after:%q}){nodes{alertID} pageInfo{hasNextPage endCursor}}}`, after))
		all = append(all, alertOrganizationIDs(t, response)...)
		var page struct {
			Alerts struct {
				PageInfo struct {
					HasNextPage bool
					EndCursor   string
				}
			}
		}
		require.NoError(t, json.Unmarshal(response.Data, &page))
		if !page.Alerts.PageInfo.HasNextPage {
			break
		}
		after = page.Alerts.PageInfo.EndCursor
	}
	require.Equal(t, []int{12, 11, 13}, all)
	// Current log access cannot be widened by replacing parent filters in a cursor.
	for _, forged := range []map[string]any{{"f": []int{21}}, {"f": nil}, {"f": []int{}, "i": h.UUID("service-b")}} {
		cursor, err := search.Cursor(forged)
		require.NoError(t, err)
		response := stepOrganizationQuery(t, h, fmt.Sprintf(`{alert(id:11){recentEvents(input:{after:%q}){nodes{alertID message}}}}`, cursor))
		require.Empty(t, response.Errors)
		require.NotContains(t, string(response.Data), "foreign-log")
		require.NotContains(t, string(response.Data), `"alertID":21`)
	}
	// Alert is not a supported DeleteAll target; this slice must not add one.
	var target assignment.TargetType
	require.Error(t, target.UnmarshalText([]byte("alert")))
}

func TestGraphQLAlertOrganizationRawParents(t *testing.T) {
	h := alertOrganizationHarness(t)
	app := alertOrganizationApp(h)
	ctx := integrationKeyOrganizationContext(t, h)
	for _, id := range []int{21, 999} {
		raw := &alert.Alert{ID: id, ServiceID: h.UUID("service-a")} // Forged ServiceID must not bless a foreign Alert.
		checks := map[string]func() error{
			"state":          func() error { _, err := app.Alert().State(ctx, raw); return err },
			"metrics":        func() error { _, err := app.Alert().Metrics(ctx, raw); return err },
			"metadata":       func() error { _, err := app.Alert().Meta(ctx, raw); return err },
			"metadata value": func() error { _, err := app.Alert().MetaValue(ctx, raw, "key"); return err },
			"logs":           func() error { _, err := app.Alert().RecentEvents(ctx, raw, nil); return err },
			"noise":          func() error { _, err := app.Alert().NoiseReason(ctx, raw); return err },
			"pending":        func() error { _, err := app.Alert().PendingNotifications(ctx, raw); return err },
			"service":        func() error { _, err := app.Alert().Service(ctx, raw); return err },
		}
		for name, check := range checks {
			t.Run(fmt.Sprintf("%s/%d", name, id), func(t *testing.T) { require.ErrorIs(t, check(), sql.ErrNoRows) })
		}
	}
	own := &alert.Alert{ID: 11, ServiceID: h.UUID("service-b")}
	svc, err := app.Alert().Service(ctx, own)
	require.NoError(t, err)
	require.Equal(t, h.UUID("service-a"), svc.ID)
	_, err = app.Alert().PendingNotifications(ctx, own)
	require.NoError(t, err)
	md, err := app.Alert().MetaValue(ctx, own, "key")
	require.NoError(t, err)
	require.Equal(t, "own-value", md)
	for _, key := range []string{"service-b", "missing"} {
		raw := &service.Service{ID: h.UUID(key)}
		counts, err := app.Service().AlertsByStatus(ctx, raw)
		require.NoError(t, err)
		require.Zero(t, counts.Acked)
		require.Zero(t, counts.Unacked)
		require.Zero(t, counts.Closed)
		stats, err := app.Service().AlertStats(ctx, raw, nil)
		require.NoError(t, err)
		require.Empty(t, stats.AlertCount)
		_, err = app.Service().RecentEvents(ctx, raw, nil)
		require.ErrorIs(t, err, sql.ErrNoRows)
	}
	logs, err := h.App().AlertLogStore.Search(ctx, &alertlog.SearchOptions{FilterAlertIDs: []int{21}})
	require.NoError(t, err)
	require.NotEmpty(t, logs)
	_, err = app.AlertLogEntry().State(ctx, &logs[0])
	require.ErrorIs(t, err, sql.ErrNoRows)
	_, err = app.AlertLogEntry().Message(ctx, &logs[0])
	require.ErrorIs(t, err, sql.ErrNoRows)
}

func TestGraphQLAlertOrganizationCreateAndDedup(t *testing.T) {
	h := alertOrganizationHarness(t)
	create := func(svc, summary string) *stepOrganizationResponse {
		return stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{createAlert(input:{serviceID:%q,summary:%q,meta:[{key:"key",value:"value"}]}){alertID serviceID meta{value}}}`, svc, summary))
	}
	before := alertOrganizationSnapshot(t, h)
	foreign := create(h.UUID("service-b"), "New alert")
	require.NotEmpty(t, foreign.Errors)
	require.Equal(t, foreign, create(h.UUID("missing"), "New alert"))
	require.Equal(t, before, alertOrganizationSnapshot(t, h))
	invalid := create(h.UUID("service-a"), " leading space")
	require.Equal(t, invalid, create(h.UUID("service-b"), " leading space"))
	require.Equal(t, invalid, create(h.UUID("missing"), " leading space"))
	own := create(h.UUID("service-a"), "New alert")
	require.Empty(t, own.Errors)
	require.Contains(t, string(own.Data), "value")
	closeMatch := func(svc, key string) *stepOrganizationResponse {
		return stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{closeMatchingAlert(input:{serviceID:%q,summary:"Matching",dedup:%q})}`, svc, key))
	}
	before = alertOrganizationSnapshot(t, h)
	foreign = closeMatch(h.UUID("service-b"), "matching")
	require.Equal(t, foreign, closeMatch(h.UUID("service-b"), "absent"))
	require.Equal(t, foreign, closeMatch(h.UUID("missing"), "matching"))
	require.NotEmpty(t, foreign.Errors)
	require.Equal(t, before, alertOrganizationSnapshot(t, h))
	require.Empty(t, closeMatch(h.UUID("service-a"), "matching").Errors)
	ctx := integrationKeyOrganizationContext(t, h)
	org := uuid.MustParse(harness.SmokeOrganizationID)
	before = alertOrganizationSnapshot(t, h)
	var lastError string
	for _, svc := range []string{"service-b", "missing"} {
		for _, key := range []string{"matching", "absent"} {
			a, created, err := h.App().AlertStore.CreateOrUpdateScoped(ctx, &alert.Alert{ServiceID: h.UUID(svc), Summary: "Matching", Dedup: alert.NewUserDedup(key)}, &org)
			require.Error(t, err)
			require.Nil(t, a)
			require.False(t, created)
			if lastError != "" {
				require.Equal(t, lastError, err.Error())
			}
			lastError = err.Error()
		}
	}
	require.Equal(t, before, alertOrganizationSnapshot(t, h))
	a, created, err := h.App().AlertStore.CreateOrUpdateScoped(ctx, &alert.Alert{ServiceID: h.UUID("service-a"), Summary: "Second", Dedup: alert.NewUserDedup("second")}, &org)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, 12, a.ID)
}

func TestGraphQLAlertOrganizationMutationsAndAtomicity(t *testing.T) {
	h := alertOrganizationHarness(t)
	request := func(q string) *stepOrganizationResponse { return stepOrganizationQuery(t, h, q) }
	before := alertOrganizationSnapshot(t, h)
	for _, q := range []string{
		`mutation{updateAlerts(input:{alertIDs:[21],newStatus:StatusAcknowledged}){alertID}}`,
		`mutation{updateAlerts(input:{alertIDs:[999],newStatus:StatusAcknowledged}){alertID}}`,
	} {
		response := request(q)
		require.Empty(t, response.Errors)
		require.Contains(t, string(response.Data), `"updateAlerts":null`)
	}
	require.Equal(t, before, alertOrganizationSnapshot(t, h))
	for _, id := range []int{21, 999} {
		response := request(fmt.Sprintf(`mutation{escalateAlerts(input:[%d]){alertID}}`, id))
		require.NotEmpty(t, response.Errors)
	}
	require.Equal(t, before, alertOrganizationSnapshot(t, h))
	for _, ids := range []string{"11,21", "11,999"} {
		done := h.ExpectBackendError("sql: no rows in result set")
		response := request(fmt.Sprintf(`mutation{updateAlerts(input:{alertIDs:[%s],noiseReason:"changed"}){alertID}}`, ids))
		done()
		require.NotEmpty(t, response.Errors)
		require.Equal(t, before, alertOrganizationSnapshot(t, h))
	}
	// Empty noise is the existing clear operation and must have the same scope.
	org := uuid.MustParse(harness.SmokeOrganizationID)
	ctx := integrationKeyOrganizationContext(t, h)
	for _, id := range []int{21, 999} {
		require.ErrorIs(t, h.App().AlertStore.UpdateFeedbackScoped(ctx, &alert.Feedback{ID: id, NoiseReason: ""}, &org), sql.ErrNoRows)
	}
	require.Equal(t, before, alertOrganizationSnapshot(t, h))
	// Human Admin has the same Organization boundary as a normal human User.
	done := h.ExpectBackendError("sql: no rows in result set")
	response := stepOrganizationPost(t, h, map[string]any{"query": `mutation{setAlertNoiseReason(input:{alertID:21,noiseReason:"admin"})}`}, h.GraphQLToken(h.UUID("admin-a")), false)
	done()
	require.NotEmpty(t, response.Errors)
	require.Equal(t, before, alertOrganizationSnapshot(t, h))
	// Bulk status updates keep exact-base existing-subset semantics, including missing IDs.
	response = request(`mutation{updateAlerts(input:{alertIDs:[11,21,999],newStatus:StatusAcknowledged}){alertID}}`)
	require.Empty(t, response.Errors)
	require.JSONEq(t, `{"updateAlerts":[{"alertID":11}]}`, string(response.Data))
	var ownStatus, foreignStatus string
	require.NoError(t, h.App().DB().QueryRow(`SELECT status FROM alerts WHERE id=11`).Scan(&ownStatus))
	require.NoError(t, h.App().DB().QueryRow(`SELECT status FROM alerts WHERE id=21`).Scan(&foreignStatus))
	require.Equal(t, "active", ownStatus)
	require.Equal(t, "triggered", foreignStatus)
	before = alertOrganizationSnapshot(t, h)
	svcMutation := func(svc string) *stepOrganizationResponse {
		return request(fmt.Sprintf(`mutation{updateAlertsByService(input:{serviceID:%q,newStatus:StatusClosed})}`, svc))
	}
	require.Equal(t, svcMutation(h.UUID("missing")), svcMutation(h.UUID("service-b")))
	require.Equal(t, before, alertOrganizationSnapshot(t, h))
	require.Empty(t, request(`mutation{escalateAlerts(input:[12]){alertID}}`).Errors)
	require.Empty(t, request(`mutation{updateAlerts(input:{alertIDs:[11,12],noiseReason:"own changed"}){alertID}}`).Errors)
	require.NoError(t, h.App().AlertStore.UpdateFeedbackScoped(ctx, &alert.Feedback{ID: 11, NoiseReason: ""}, &org))
	cleared, err := alertOrganizationApp(h).Alert().NoiseReason(ctx, &alert.Alert{ID: 11})
	require.NoError(t, err)
	require.Nil(t, cleared)
	require.Empty(t, svcMutation(h.UUID("service-a")).Errors)
}

func TestAlertOrganizationNonHumanCompatibilityAndFK(t *testing.T) {
	h := alertOrganizationHarness(t)
	app := alertOrganizationApp(h)
	db := h.App().DB()
	for _, ctx := range []context.Context{
		permission.SystemContext(context.Background(), "AlertOrganizationCompatibility"),
		permission.UserSourceContext(context.Background(), h.UUID("user-a"), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}),
		permission.UserSourceContext(context.Background(), h.UUID("user-a"), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeNotificationCallback, ID: uuid.NewString()}),
	} {
		foreign, err := app.Query().Alert(ctx, 21)
		require.NoError(t, err)
		require.Equal(t, 21, foreign.ID)
		rows, err := h.App().AlertStore.SearchScoped(ctx, nil, nil)
		require.NoError(t, err)
		require.Len(t, rows, 6)
		_, _, err = h.App().AlertStore.CreateOrUpdate(ctx, &alert.Alert{ServiceID: h.UUID("service-b"), Summary: "Matching", Dedup: alert.NewUserDedup("matching")})
		require.NoError(t, err)
	}
	ctx := integrationKeyOrganizationContext(t, h)
	org := uuid.MustParse(harness.SmokeOrganizationID)
	zero := uuid.Nil
	_, err := h.App().AlertStore.FindOneScoped(ctx, 21, &zero)
	require.Error(t, err)
	_, err = h.App().AlertStore.SearchScoped(ctx, nil, &zero)
	require.Error(t, err)
	_, err = h.App().AlertLogStore.SearchScoped(ctx, nil, &zero)
	require.Error(t, err)
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `SELECT 1 FROM services WHERE id=$1 FOR UPDATE`, h.UUID("service-a"))
	require.NoError(t, err)
	checkCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	require.NoError(t, h.App().AlertStore.CheckOrganization(checkCtx, db, 11, &org), "authorization itself must not acquire a Service row lock")
	require.NoError(t, tx.Rollback())
	var independentOwner bool
	require.NoError(t, db.QueryRow(`SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='organization_id')`).Scan(&independentOwner))
	require.False(t, independentOwner)
	_, err = db.Exec(`DELETE FROM services WHERE id=$1`, h.UUID("service-a"))
	require.NoError(t, err)
	var count int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM alerts WHERE id IN (11,12,13)`).Scan(&count))
	require.Zero(t, count)
	require.ErrorIs(t, h.App().AlertStore.CheckOrganization(ctx, db, 11, &org), sql.ErrNoRows)
	_, _, err = h.App().AlertStore.CreateOrUpdateScoped(ctx, &alert.Alert{ServiceID: h.UUID("service-a"), Summary: "Gone"}, &org)
	require.Error(t, err)
	rows, err := h.App().AlertStore.UpdateManyAlertStatusScoped(ctx, alert.StatusClosed, []int{11, 21}, nil, &org)
	require.NoError(t, err)
	require.Empty(t, rows)
}
