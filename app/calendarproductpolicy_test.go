package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/auth/authtoken"
	"github.com/target/goalert/calsub"
	"github.com/target/goalert/config"
	"github.com/target/goalert/keyring"
	"github.com/target/goalert/migrate"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util/log"
)

const calendarHardDisabled = true

// This API-only fixture exercises production middleware, resolvers, config
// persistence, and stores without starting notification providers. DB_URL must
// point to a disposable PostgreSQL instance with database-creation permission.
type calendarPolicyRuntime struct {
	t         *testing.T
	app       *App
	cfg       Config
	pool      *pgxpool.Pool
	done      chan error
	users     [2]string
	schedules [2]string
	admin     string
}

func newCalendarPolicyRuntime(t *testing.T) *calendarPolicyRuntime {
	t.Helper()
	base := os.Getenv("DB_URL")
	if base == "" {
		t.Skip("DB_URL is required for PostgreSQL Calendar product-policy controls")
	}
	ctx := context.Background()
	control, err := pgx.Connect(ctx, base)
	require.NoError(t, err)
	name := "calendar_policy_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = control.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	require.NoError(t, err)
	h := &calendarPolicyRuntime{t: t, admin: uuid.NewString()}
	t.Cleanup(func() {
		h.stop()
		if h.pool != nil {
			h.pool.Close()
		}
		var sessions int
		require.NoError(t, control.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=$1`, name).Scan(&sessions))
		require.Zero(t, sessions)
		_, err := control.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize())
		require.NoError(t, err)
		require.NoError(t, control.Close(ctx))
	})
	u, err := url.Parse(base)
	require.NoError(t, err)
	u.Path = "/" + name
	logger := log.NewLogger()
	logger.SetOutput(io.Discard)
	_, err = migrate.ApplyAll(log.WithLogger(ctx, logger), u.String())
	require.NoError(t, err)
	h.pool, err = pgxpool.New(ctx, u.String())
	require.NoError(t, err)
	for i := range h.users {
		org := uuid.NewString()
		h.users[i], h.schedules[i] = uuid.NewString(), uuid.NewString()
		_, err = h.pool.Exec(ctx, `INSERT INTO organizations(id,classification,display_name,canonical_name) VALUES($1,'NORMAL',$2,$2)`, org, fmt.Sprintf("calendar-policy-%d", i))
		require.NoError(t, err)
		_, err = h.pool.Exec(ctx, `INSERT INTO normal_organizations(organization_id,organization_classification,corporate_mapping_key,iana_time_zone) VALUES($1,'NORMAL',$2,'Etc/UTC')`, org, org)
		require.NoError(t, err)
		_, err = h.pool.Exec(ctx, `INSERT INTO users(id,name,email,role) VALUES($1,$2,'','user')`, h.users[i], fmt.Sprintf("Calendar Policy User %d", i))
		require.NoError(t, err)
		_, err = h.pool.Exec(ctx, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count) VALUES($1,$2,'NORMAL',$2,'ORG_MEMBER','EXACTLY_ONE',now(),'calendar-policy-test',1)`, h.users[i], org)
		require.NoError(t, err)
		_, err = h.pool.Exec(ctx, `INSERT INTO schedules(id,name,time_zone,organization_id) VALUES($1,$2,'Etc/UTC',$3)`, h.schedules[i], fmt.Sprintf("Calendar Policy Schedule %d", i), org)
		require.NoError(t, err)
		_, err = h.pool.Exec(ctx, `INSERT INTO schedule_rules(id,schedule_id,start_time,end_time,tgt_user_id) VALUES($1,$2,'00:00:00','00:00:00',$3)`, uuid.NewString(), h.schedules[i], h.users[i])
		require.NoError(t, err)
		if i == 0 {
			_, err = h.pool.Exec(ctx, `INSERT INTO users(id,name,email,role) VALUES($1,'Calendar Policy Admin','','admin')`, h.admin)
			require.NoError(t, err)
			_, err = h.pool.Exec(ctx, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count) SELECT $1,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count FROM user_organization_assignments WHERE user_id=$2`, h.admin, h.users[0])
			require.NoError(t, err)
		}
	}
	h.cfg = Defaults()
	h.cfg.LegacyLogger = logger
	h.cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	h.cfg.ListenAddr = "127.0.0.1:0"
	h.cfg.APIOnly = true
	h.cfg.DBURL = u.String()
	h.cfg.DBMaxOpen = 16
	h.cfg.DBMaxIdle = 2
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	h.cfg.EncryptionKeys = keyring.Keys{key, nil}
	h.start()
	return h
}

func (h *calendarPolicyRuntime) start() {
	var err error
	h.app, err = NewApp(h.cfg, h.pool)
	require.NoError(h.t, err)
	h.done = make(chan error, 1)
	go func() { h.done <- h.app.Run(context.Background()) }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(h.t, h.app.WaitForStartup(ctx))
}

func (h *calendarPolicyRuntime) stop() {
	if h.app == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(h.t, h.app.Shutdown(ctx))
	require.NoError(h.t, <-h.done)
	h.app = nil
}

func (h *calendarPolicyRuntime) request(who, method, path, contentType string, body []byte) (int, []byte) {
	h.t.Helper()
	req, err := http.NewRequest(method, h.app.URL()+path, bytes.NewReader(body))
	require.NoError(h.t, err)
	req.Header.Set("Content-Type", contentType)
	if who != "" {
		tok, err := h.app.AuthHandler.CreateSession(context.Background(), "calendar-policy-test", who)
		require.NoError(h.t, err)
		raw, err := tok.Encode(h.app.SessionKeyring.Sign)
		require.NoError(h.t, err)
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: raw})
	}
	return h.do(req)
}

func (h *calendarPolicyRuntime) do(req *http.Request) (int, []byte) {
	h.t.Helper()
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	// Do not print the request or credentials on transport failure.
	if err != nil {
		h.t.Fatal("Calendar policy HTTP control could not complete")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(h.t, err)
	return res.StatusCode, body
}

type calendarGraphQLResult struct {
	Data   map[string]json.RawMessage
	Errors []struct{ Message string }
}

func (h *calendarPolicyRuntime) query(who, query string) calendarGraphQLResult {
	h.t.Helper()
	payload, err := json.Marshal(map[string]string{"query": query})
	require.NoError(h.t, err)
	code, body := h.request(who, "POST", "/api/graphql", "application/json", payload)
	require.Equal(h.t, http.StatusOK, code)
	var result calendarGraphQLResult
	require.NoError(h.t, json.Unmarshal(body, &result))
	return result
}

func calendarObservation(t *testing.T, name string, got, want any) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"name": name, "value": got})
	require.NoError(t, err)
	t.Logf("CALENDAR_OBSERVATION %s", data)
	require.Equal(t, want, got, name)
}

func (h *calendarPolicyRuntime) historical(owner, schedule string) authtoken.Token {
	h.t.Helper()
	tok := authtoken.Token{Type: authtoken.TypeCalSub, Version: 2, ID: uuid.New(), CreatedAt: time.Now().Add(-24 * time.Hour).Truncate(time.Second)}
	_, err := h.app.DB().Exec(`INSERT INTO user_calendar_subscriptions(id,name,user_id,schedule_id,config,created_at,last_access) VALUES($1,$2,$3,$4,'{"FullSchedule":true,"ReminderMinutes":[5]}',$5,'2000-01-01 UTC')`, tok.ID, "Historical "+tok.ID.String(), owner, schedule, tok.CreatedAt)
	require.NoError(h.t, err)
	return tok
}

func TestCalendarProductPolicyConfigPersistence(t *testing.T) {
	h := newCalendarPolicyRuntime(t)
	ctx := permission.UserContext(context.Background(), h.admin, permission.RoleAdmin)
	check := func(label string) {
		t.Helper()
		calendarObservation(t, label+"/store", h.app.ConfigStore.Config().General.DisableCalendarSubscriptions, calendarHardDisabled)
		for _, all := range []bool{false, true} {
			who := h.users[0]
			if all {
				who = h.admin
			}
			res := h.query(who, fmt.Sprintf(`{config(all:%t){id value}}`, all))
			require.Empty(t, res.Errors)
			var values []struct{ ID, Value string }
			require.NoError(t, json.Unmarshal(res.Data["config"], &values))
			found := false
			for _, value := range values {
				if value.ID == "General.DisableCalendarSubscriptions" {
					found = true
					calendarObservation(t, fmt.Sprintf("%s/graphql-all-%t", label, all), value.Value, fmt.Sprint(calendarHardDisabled))
				}
			}
			require.True(t, found)
		}
		res := h.query(h.users[0], fmt.Sprintf(`mutation{createUserCalendarSubscription(input:{name:%q,scheduleID:%q}){id url}}`, label, h.schedules[0]))
		calendarObservation(t, label+"/create-rejected", len(res.Errors) != 0, calendarHardDisabled)
		if calendarHardDisabled {
			require.Equal(t, "disabled by administrator", res.Errors[0].Message)
			require.Empty(t, res.Data)
		}
	}
	check("omitted-default")
	for _, raw := range []string{`{}`, `{"General":{"DisableCalendarSubscriptions":false,"ApplicationName":"Neighbor control"}}`} {
		_, err := h.app.ConfigStore.SetConfigData(ctx, nil, []byte(raw)) // CLI set-config uses this same raw import path.
		require.NoError(t, err)
		require.NoError(t, h.app.ConfigStore.Reload(ctx))
	}
	check("persisted-false-reload")
	require.Equal(t, "Neighbor control", h.app.ConfigStore.Config().ApplicationName())
	res := h.query(h.admin, `mutation{setConfig(input:[{id:"General.DisableCalendarSubscriptions",value:"false"}])}`)
	require.Empty(t, res.Errors)
	check("admin-setconfig-false")
	res = h.query(h.users[0], `mutation{setConfig(input:[{id:"General.DisableCalendarSubscriptions",value:"false"}])}`)
	require.Len(t, res.Errors, 1)
	calendarObservation(t, "ordinary-config-write", res.Errors[0].Message, "access denied")
	code, _ := h.request(h.admin, "PUT", "/api/v2/config", "application/json", []byte(`{"General":{"DisableCalendarSubscriptions":false}}`))
	require.Equal(t, http.StatusNoContent, code)
	check("http-import-false")
	_, _, raw, err := h.app.ConfigStore.ConfigData(ctx, nil)
	require.NoError(t, err)
	var persisted config.Config
	require.NoError(t, json.Unmarshal(raw, &persisted))
	calendarObservation(t, "raw-false-preserved", persisted.General.DisableCalendarSubscriptions, false)
	h.stop()
	h.start()
	check("restart-false")
	h.stop()
	h.cfg.InitialConfig = &config.Config{}
	h.start()
	check("initialconfig-false")
}

func TestCalendarProductPolicyHistoricalSurfaces(t *testing.T) {
	h := newCalendarPolicyRuntime(t)
	for _, rawDisabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("stored-disabled-%t", rawDisabled), func(t *testing.T) {
			cfg := config.Config{}
			cfg.General.DisableCalendarSubscriptions = rawDisabled
			ctx := permission.UserContext(cfg.Context(context.Background()), h.users[0], permission.RoleUser)
			admin := permission.UserContext(context.Background(), h.admin, permission.RoleAdmin)
			require.NoError(t, h.app.ConfigStore.SetConfig(admin, cfg))
			for _, item := range []struct{ label, owner, schedule string }{
				{"own", h.users[0], h.schedules[0]},
				{"foreign-schedule", h.users[0], h.schedules[1]},
				{"foreign-owner", h.users[1], h.schedules[1]},
			} {
				tok := h.historical(item.owner, item.schedule)
				label := fmt.Sprintf("stored-%t/%s", rawDisabled, item.label)
				res := h.query(h.users[0], fmt.Sprintf(`{userCalendarSubscription(id:%q){id name reminderMinutes fullSchedule scheduleID lastAccess disabled url}}`, tok.ID))
				calendarObservation(t, label+"/read-rejected", len(res.Errors) != 0, calendarHardDisabled)
				if calendarHardDisabled {
					require.Contains(t, []string{"", "null"}, string(res.Data["userCalendarSubscription"]))
				} else {
					var metadata map[string]json.RawMessage
					require.NoError(t, json.Unmarshal(res.Data["userCalendarSubscription"], &metadata))
					for _, field := range []string{"id", "name", "reminderMinutes", "fullSchedule", "scheduleID", "lastAccess", "disabled"} {
						require.Contains(t, metadata, field)
					}
				}
				sub, err := h.app.CalSubStore.FindOne(ctx, tok.ID.String())
				calendarObservation(t, label+"/store-read-rejected", err != nil && sub == nil, calendarHardDisabled)
				res = h.query(h.users[0], fmt.Sprintf(`mutation{updateUserCalendarSubscription(input:{id:%q,name:"Changed"})}`, tok.ID))
				wantRejected := calendarHardDisabled || item.owner != h.users[0]
				calendarObservation(t, label+"/update-rejected", len(res.Errors) != 0, wantRejected)
				if calendarHardDisabled {
					require.Equal(t, "disabled by administrator", res.Errors[0].Message)
				}
				var name string
				require.NoError(t, h.app.DB().QueryRow(`SELECT name FROM user_calendar_subscriptions WHERE id=$1`, tok.ID).Scan(&name))
				calendarObservation(t, label+"/update-mutated", name == "Changed", !wantRejected)
				before := h.lastAccess(tok.ID)
				authorized, err := h.app.CalSubStore.Authorize(context.Background(), tok)
				calendarObservation(t, label+"/authorize-rejected", err != nil, calendarHardDisabled)
				calendarObservation(t, label+"/calendar-source", permission.Source(authorized) != nil, !calendarHardDisabled)
				calendarObservation(t, label+"/auth-last-access-changed", !h.lastAccess(tok.ID).Equal(before), !calendarHardDisabled)
				signed, err := tok.Encode(h.app.APIKeyring.Sign)
				require.NoError(t, err)
				for _, accept := range []string{"application/json", "text/calendar"} {
					before := h.lastAccess(tok.ID)
					req, err := http.NewRequest("GET", h.app.URL()+"/api/v2/calendar", nil)
					require.NoError(t, err)
					req.Header.Set("Authorization", "Bearer "+signed)
					req.Header.Set("Accept", accept)
					code, body := h.do(req)
					want := http.StatusOK
					if calendarHardDisabled {
						want = http.StatusUnauthorized
					} else if rawDisabled {
						want = http.StatusForbidden
					}
					calendarObservation(t, label+"/"+accept+"-status", code, want)
					if want != http.StatusOK {
						require.NotContains(t, string(body), "Calendar Policy")
						require.NotContains(t, string(body), "Shifts")
					} else {
						require.Contains(t, string(body), "Calendar Policy")
					}
					calendarObservation(t, label+"/"+accept+"-last-access-changed", !h.lastAccess(tok.ID).Equal(before), !calendarHardDisabled)
				}
				res = h.query(h.users[0], fmt.Sprintf(`mutation{deleteAll(input:[{type:calendarSubscription,id:%q}])}`, tok.ID))
				require.Empty(t, res.Errors)
				var remaining int
				require.NoError(t, h.app.DB().QueryRow(`SELECT count(*) FROM user_calendar_subscriptions WHERE id=$1`, tok.ID).Scan(&remaining))
				calendarObservation(t, label+"/cleanup-removed", remaining == 0, item.owner == h.users[0])
			}
			res := h.query(h.users[0], `{user{calendarSubscriptions{id name}}}`)
			calendarObservation(t, fmt.Sprintf("stored-%t/list-rejected", rawDisabled), len(res.Errors) != 0, calendarHardDisabled)
			if calendarHardDisabled {
				require.Contains(t, []string{"", "null"}, string(res.Data["user"]))
			}
			subs, err := h.app.CalSubStore.FindAllByUser(ctx, h.users[0])
			calendarObservation(t, fmt.Sprintf("stored-%t/store-list-rejected", rawDisabled), err != nil && subs == nil, calendarHardDisabled)
			var countBefore, countAfter int
			require.NoError(t, h.app.DB().QueryRow(`SELECT count(*) FROM user_calendar_subscriptions`).Scan(&countBefore))
			res = h.query(h.users[0], fmt.Sprintf(`mutation{createUserCalendarSubscription(input:{name:%q,scheduleID:%q}){id url}}`, fmt.Sprintf("Create %t", rawDisabled), h.schedules[1]))
			calendarObservation(t, fmt.Sprintf("stored-%t/create-rejected", rawDisabled), len(res.Errors) != 0, calendarHardDisabled || rawDisabled)
			if calendarHardDisabled || rawDisabled {
				require.Equal(t, "disabled by administrator", res.Errors[0].Message)
				require.Empty(t, res.Data, "no creation object or token")
			}
			require.NoError(t, h.app.DB().QueryRow(`SELECT count(*) FROM user_calendar_subscriptions`).Scan(&countAfter))
			calendarObservation(t, fmt.Sprintf("stored-%t/create-no-row", rawDisabled), countBefore == countAfter, calendarHardDisabled || rawDisabled)
		})
	}
}

func (h *calendarPolicyRuntime) lastAccess(id uuid.UUID) time.Time {
	h.t.Helper()
	var stamp time.Time
	require.NoError(h.t, h.app.DB().QueryRow(`SELECT last_access FROM user_calendar_subscriptions WHERE id=$1`, id).Scan(&stamp))
	return stamp
}

func TestCalendarProductPolicyBeforePostgresLocks(t *testing.T) {
	h := newCalendarPolicyRuntime(t)
	tok := h.historical(h.users[1], h.schedules[1])
	ctx := permission.UserContext(config.Config{}.Context(context.Background()), h.users[0], permission.RoleUser)
	tx, err := h.app.DB().BeginTx(context.Background(), nil)
	require.NoError(t, err)
	defer tx.Rollback()
	// ACCESS EXCLUSIVE conflicts even with a metadata SELECT. First prove
	// that the control really blocks the historical SQL, then retain the lock
	// while calling the production Store, GraphQL, and HTTP auth boundaries.
	_, err = tx.Exec(`LOCK TABLE user_calendar_subscriptions IN ACCESS EXCLUSIVE MODE`)
	require.NoError(t, err)
	for _, query := range []string{
		`SELECT id FROM user_calendar_subscriptions WHERE id=$1 FOR UPDATE`,
		`UPDATE user_calendar_subscriptions SET last_access=now() WHERE id=$1`,
	} {
		probe, err := h.app.DB().BeginTx(context.Background(), nil)
		require.NoError(t, err)
		_, err = probe.Exec(`SET LOCAL lock_timeout='100ms'`)
		require.NoError(t, err)
		_, err = probe.Exec(query, tok.ID)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "55P03", pgErr.Code)
		require.NoError(t, probe.Rollback())
	}
	if !calendarHardDisabled {
		// The exact-base differential runs this same control with a bounded
		// context and observes the historical lock wait without hanging.
		blocked, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		queryTx, err := h.app.DB().BeginTx(blocked, nil)
		require.NoError(t, err)
		defer queryTx.Rollback()
		_, err = h.app.CalSubStore.FindOneForUpdate(blocked, queryTx, tok.ID.String())
		require.Error(t, err)
		calendarObservation(t, "postgres/update-before-table-access", err.Error() == "disabled by administrator", false)
		blockedAuth, cancelAuth := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancelAuth()
		_, err = h.app.CalSubStore.Authorize(blockedAuth, tok)
		require.Error(t, err)
		calendarObservation(t, "postgres/auth-before-table-access", permission.IsPermissionError(err), false)
		require.NoError(t, tx.Rollback())
		calendarObservation(t, "postgres/last-access-unchanged", h.lastAccess(tok.ID).Year() == 2000, true)
		return
	}
	requestCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, err = h.app.CalSubStore.FindOneForUpdate(requestCtx, nil, tok.ID.String())
	require.EqualError(t, err, "disabled by administrator")
	_, err = h.app.CalSubStore.FindOne(requestCtx, tok.ID.String())
	require.EqualError(t, err, "disabled by administrator")
	_, err = h.app.CalSubStore.FindAllByUser(requestCtx, h.users[0])
	require.EqualError(t, err, "disabled by administrator")
	err = h.app.CalSubStore.UpdateTx(requestCtx, nil, &calsub.Subscription{ID: tok.ID.String(), UserID: h.users[0]})
	require.EqualError(t, err, "disabled by administrator")
	res := h.query(h.users[0], fmt.Sprintf(`mutation{updateUserCalendarSubscription(input:{id:%q,name:"Blocked"})}`, tok.ID))
	require.Len(t, res.Errors, 1)
	require.Equal(t, "disabled by administrator", res.Errors[0].Message)
	calendarObservation(t, "postgres/update-before-table-access", true, true)
	authorized, err := h.app.CalSubStore.Authorize(requestCtx, tok)
	require.True(t, permission.IsPermissionError(err))
	require.Nil(t, permission.Source(authorized))
	signed, err := tok.Encode(h.app.APIKeyring.Sign)
	require.NoError(t, err)
	req, err := http.NewRequest("GET", h.app.URL()+"/api/v2/calendar", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+signed)
	code, _ := h.do(req)
	require.Equal(t, http.StatusUnauthorized, code)
	calendarObservation(t, "postgres/auth-before-table-access", true, true)
	require.NoError(t, tx.Rollback())
	calendarObservation(t, "postgres/last-access-unchanged", h.lastAccess(tok.ID).Year() == 2000, true)
}

func TestCalendarProductPolicyCleanupCascades(t *testing.T) {
	h := newCalendarPolicyRuntime(t)
	for _, parent := range []string{"schedules", "users"} {
		tok := h.historical(h.users[0], h.schedules[0])
		id := h.schedules[0]
		if parent == "users" {
			id = h.users[0]
		}
		tx, err := h.app.DB().BeginTx(context.Background(), nil)
		require.NoError(t, err)
		_, err = tx.Exec("DELETE FROM "+parent+" WHERE id=$1", id)
		require.NoError(t, err)
		var remaining int
		require.NoError(t, tx.QueryRow(`SELECT count(*) FROM user_calendar_subscriptions WHERE id=$1`, tok.ID).Scan(&remaining))
		calendarObservation(t, parent+"/cascade", remaining, 0)
		require.NoError(t, tx.Rollback())
	}
}
