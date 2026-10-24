package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"net"
	"net/http/httptest"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
	sloglogrus "github.com/samber/slog-logrus/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/alert"
	"github.com/target/goalert/app"
	"github.com/target/goalert/config"
	"github.com/target/goalert/devtools/mockslack"
	"github.com/target/goalert/devtools/mocktwilio"
	"github.com/target/goalert/devtools/pgdump-lite"
	"github.com/target/goalert/devtools/pgmocktime"
	"github.com/target/goalert/expflag"
	"github.com/target/goalert/migrate"
	"github.com/target/goalert/notification/twilio"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/user"
	"github.com/target/goalert/user/notificationrule"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/util/timeutil"
)

var (
	dbURLStr string
	dbURL    *url.URL
)

func init() {
	dbURLStr = os.Getenv("DB_URL")
	if dbURLStr == "" {
		dbURLStr = "postgres://goalert@127.0.0.1:5432?sslmode=disable"
	}
	var err error
	dbURL, err = url.Parse(dbURLStr)
	if err != nil {
		panic("parse smoke database URL: " + safeDBError(err))
	}
}

// Database errors can contain the original DSN, query parameters, or server
// messages containing credentials. Only emit fixed classifications and a
// validated SQLSTATE; never retain or format the original error in diagnostics.
func safeDBError(err error) string {
	var pgErr *pgconn.PgError
	var parseErr *pgconn.ParseConfigError
	var connectErr *pgconn.ConnectError
	var netErr net.Error
	switch {
	case errors.As(err, &pgErr):
		code := pgErr.Code
		if len(code) == 5 && strings.IndexFunc(code, func(r rune) bool {
			return (r < '0' || r > '9') && (r < 'A' || r > 'Z')
		}) == -1 {
			return "PostgreSQL error (SQLSTATE " + code + ")"
		}
		return "PostgreSQL error (SQLSTATE unavailable)"
	case errors.As(err, &parseErr):
		return "invalid PostgreSQL connection configuration"
	case errors.Is(err, context.DeadlineExceeded):
		return "database operation timed out"
	case errors.Is(err, context.Canceled):
		return "database operation canceled"
	case errors.As(err, &connectErr):
		return "PostgreSQL connection error"
	case errors.As(err, &netErr):
		return "database network error"
	default:
		return "database error (details withheld)"
	}
}

type dbErrorReporter interface {
	Helper()
	Fatalf(string, ...any)
	Errorf(string, ...any)
}

func requireDBNoError(t dbErrorReporter, err error, operation string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", operation, safeDBError(err))
	}
}

func assertDBNoError(t dbErrorReporter, err error, operation string) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: %s", operation, safeDBError(err))
	}
}

func stopForDebugDB(t dbErrorReporter, name string) {
	t.Helper()
	t.Fatalf("DEBUG DB: database %q; inspect using your existing PostgreSQL connection settings and this database name (credentials omitted)", name)
}

func DBURL(name string) string {
	if name == "" {
		return dbURLStr
	}
	u := *dbURL
	u.Path = "/" + url.PathEscape(name)
	return u.String()
}

// Harness is a helper for smoketests. It deals with assertions, database management, and backend monitoring during tests.
type Harness struct {
	phoneCCG, uuidG, emailG *DataGen
	t                       *testing.T
	closing                 bool

	appPool *pgxpool.Pool

	rcsSenderID string
	rcsMsgSvcID string
	msgSvcID    string
	expFlags    expflag.FlagSet

	tw  *twilioAssertionAPI
	twS *httptest.Server

	cfg config.Config

	appCfg app.Config

	email     *emailServer
	slack     *slackServer
	slackS    *httptest.Server
	slackApp  mockslack.AppInfo
	slackUser mockslack.UserInfo

	pgTime *pgmocktime.Mocker

	ignoreErrors          []string
	expectedBackendErrors []*expectedBackendError

	backend     *app.App
	backendLogs io.Closer
	logsDone    chan struct{}

	dbURL  string
	dbName string
	mx     sync.Mutex

	userGeneratedIndex int

	gqlSessions map[string]string
}

func (h *Harness) Config() config.Config {
	return h.cfg
}

// NewHarness will create a new database, perform `migrateSteps` migrations, inject `initSQL` and return a new Harness bound to
// the result. It starts a backend process pre-configured to a mock twilio server for monitoring notifications as well.
func NewHarness(t *testing.T, initSQL, migrationName string) *Harness {
	t.Helper()
	return NewHarnessWithFlags(t, initSQL, migrationName, nil)
}

// NewHarnessWithFlags is the same as NewHarness, but allows passing in a set of experimental flags to be used for the test.
func NewHarnessWithFlags(t *testing.T, initSQL, migrationName string, fs expflag.FlagSet) *Harness {
	stdlog.SetOutput(io.Discard)
	t.Helper()
	h := NewStoppedHarnessWithFlags(t, initSQL, nil, migrationName, fs)
	h.Start()
	return h
}

func (h *Harness) App() *app.App { return h.backend }

func NewHarnessWithData(t *testing.T, initSQL string, sqlData interface{}, migrationName string) *Harness {
	t.Helper()
	h := NewStoppedHarness(t, initSQL, sqlData, migrationName)
	h.Start()
	return h
}

// NewHarnessDebugDB works like NewHarness, but fails the test immediately after
// migrations have been run. It is used to debug data & queries from a smoketest.
//
// Note that the now() function will be locked to the init timestamp for inspection.
func NewHarnessDebugDB(t *testing.T, initSQL, migrationName string) *Harness {
	t.Helper()
	h := NewStoppedHarness(t, initSQL, nil, migrationName)
	h.Migrate("")

	stopForDebugDB(t, h.dbName)
	return nil
}

const (
	twilioAuthToken  = "11111111111111111111111111111111"
	twilioAccountSID = "AC00000000000000000000000000000000"
	mailgunAPIKey    = "key-00000000000000000000000000000000"
)

// NewStoppedHarness will create a NewHarness, but will not call Start.
func NewStoppedHarness(t *testing.T, initSQL string, sqlData interface{}, migrationName string) *Harness {
	t.Helper()
	return NewStoppedHarnessWithFlags(t, initSQL, sqlData, migrationName, nil)
}

// NewStoppedHarnessWithFlags is the same as NewStoppedHarness, but allows
// passing in a set of experimental flags to be used for the test.
func NewStoppedHarnessWithFlags(t *testing.T, initSQL string, sqlData interface{}, migrationName string, expFlags expflag.FlagSet) *Harness {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping Harness tests for short mode")
	}

	t.Log("Connecting to smoke test database")
	name := strings.ReplaceAll("smoketest_"+time.Now().Format("2006_01_02_15_04_05")+uuid.New().String(), "-", "")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, DBURL(""))
	requireDBNoError(t, err, "connect to db")
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, "create database "+sqlutil.QuoteID(name))
	requireDBNoError(t, err, "create db")
	conn.Close(ctx)

	t.Logf("created test database %q", name)

	twCfg := mocktwilio.Config{
		AuthToken:    twilioAuthToken,
		AccountSID:   twilioAccountSID,
		MinQueueTime: 100 * time.Millisecond, // until we have a stateless backend for answering calls
	}

	pgTime, err := pgmocktime.New(ctx, DBURL(name))
	requireDBNoError(t, err, "create pgmocktime")

	h := &Harness{
		uuidG:    NewDataGen(t, "UUID", DataGenFunc(GenUUID)),
		phoneCCG: NewDataGen(t, "Phone", DataGenArgFunc(GenPhoneCC)),
		emailG:   NewDataGen(t, "Email", DataGenFunc(func() string { return GenUUID() + "@example.com" })),
		dbName:   name,
		dbURL:    DBURL(name),
		pgTime:   pgTime,

		gqlSessions: make(map[string]string),

		expFlags: expFlags,

		t: t,
	}
	h.email = newEmailServer(h)

	h.tw = newTwilioAssertionAPI(func() {
		h.FastForward(time.Minute)
		h.Trigger()
	}, func(num string) string {
		id, ok := h.phoneCCG.names[num]
		if !ok {
			return num
		}

		return fmt.Sprintf("%s/Phone(%s)", num, id)
	}, mocktwilio.NewServer(twCfg), h.phoneCCG.Get("twilio"))

	h.twS = httptest.NewServer(h.tw)

	err = h.pgTime.Inject(ctx)
	requireDBNoError(t, err, "inject pgmocktime")
	err = h.pgTime.SetSpeed(ctx, 0)
	requireDBNoError(t, err, "freeze pgmocktime")

	h.Migrate(migrationName)
	h.ensureSmokeOrganization()
	h.initSlack()
	h.execQuery(initSQL, sqlData)
	h.ensureSmokeUserOrganizationAssignments()

	return h
}

func (h *Harness) Start() {
	h.t.Helper()
	h.StartWithAppCfgHook(nil)
}

func (h *Harness) StartWithAppCfgHook(fn func(*app.Config)) {
	h.t.Helper()

	var cfg config.Config
	cfg.General.DisableMessageBundles = true
	cfg.Slack.Enable = true
	cfg.Slack.AccessToken = h.slackApp.AccessToken
	cfg.Slack.ClientID = h.slackApp.ClientID
	cfg.Slack.ClientSecret = h.slackApp.ClientSecret
	cfg.Slack.SigningSecret = SlackTestSigningSecret
	cfg.Twilio.Enable = true
	cfg.Twilio.AccountSID = twilioAccountSID
	cfg.Twilio.AuthToken = twilioAuthToken
	cfg.Twilio.FromNumber = h.phoneCCG.Get("twilio")

	cfg.SMTP.Enable = true
	cfg.SMTP.Address = h.email.Addr()
	cfg.SMTP.DisableTLS = true
	cfg.SMTP.From = "goalert-test@localhost"

	cfg.Webhook.Enable = true

	cfg.Mailgun.Enable = true
	cfg.Mailgun.APIKey = mailgunAPIKey
	cfg.Mailgun.EmailDomain = "smoketest.example.com"
	h.cfg = cfg

	l := log.NewLogger()
	l.ErrorsOnly()
	// Migration failures are reported through the credential-safe diagnostic below.
	l.SetOutput(io.Discard)
	_, err := migrate.ApplyAll(log.WithLogger(context.Background(), l), h.dbURL)
	requireDBNoError(h.t, err, "migrate backend")
	h.ensureSmokeOrganization()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = h.pgTime.SetSpeed(ctx, 1)
	requireDBNoError(h.t, err, "resume flow of time")

	appCfg := app.Defaults()
	appCfg.ForceRiverDBTime = true
	appCfg.ExpFlags = h.expFlags
	appCfg.LegacyLogger = log.NewLogger()
	appCfg.Logger = slog.New(sloglogrus.Option{
		Logger: appCfg.LegacyLogger.Logrus(),
	}.NewLogrusHandler())
	appCfg.ListenAddr = "localhost:0"
	appCfg.Verbose = true
	appCfg.JSON = true
	appCfg.DBURL = h.dbURL
	appCfg.TwilioBaseURL = h.twS.URL
	appCfg.DBMaxOpen = 5
	appCfg.SlackBaseURL = h.slackS.URL
	appCfg.SMTPListenAddr = "localhost:0"
	appCfg.EmailIntegrationDomain = "smoketest.example.com"
	appCfg.InitialConfig = &h.cfg
	h.appCfg = appCfg

	r, w := io.Pipe()
	h.backendLogs = w
	h.logsDone = make(chan struct{})

	appCfg.LegacyLogger.EnableJSON()
	appCfg.LegacyLogger.SetOutput(w)

	go h.watchBackendLogs(r)

	poolCfg, err := pgxpool.ParseConfig(h.dbURL)
	requireDBNoError(h.t, err, "parse db url")
	poolCfg.MaxConns = 5

	h.appPool, err = pgxpool.NewWithConfig(ctx, poolCfg)
	requireDBNoError(h.t, err, "create pgx pool")

	if fn != nil {
		fn(&appCfg)
	}

	h.backend, err = app.NewApp(appCfg, h.appPool)
	requireDBNoError(h.t, err, "start backend")
	h.TwilioNumber("") // register default number
	h.slack.SetActionURL(h.slackApp.ClientID, h.backend.URL()+"/api/v2/slack/message-action")

	go func() {
		assertDBNoError(h.t, h.backend.Run(context.Background()), "run backend") // cannot fail immediately from a background goroutine
	}()
	err = h.backend.WaitForStartup(ctx)
	requireDBNoError(h.t, err, "start backend")
}

// RestartGoAlertWithConfig will restart the backend with the provided config.
func (h *Harness) RestartGoAlertWithConfig(cfg config.Config) {
	h.t.Helper()
	h.RestartGoAlertWithAppCfgHook(func(c *app.Config) {
		c.InitialConfig = &cfg
	})
}

// RestartGoAlertWithAppCfgHook will restart the backend with the provided config hook.
func (h *Harness) RestartGoAlertWithAppCfgHook(reconfig func(*app.Config)) {
	h.t.Helper()

	h.t.Logf("Stopping backend for restart")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := h.backend.Shutdown(ctx)
	assertDBNoError(h.t, err, "shutdown backend cleanly")

	h.t.Logf("Restarting backend")
	reconfig(&h.appCfg)
	h.backend, err = app.NewApp(h.appCfg, h.appPool)
	requireDBNoError(h.t, err, "start backend")
	h.slack.SetActionURL(h.slackApp.ClientID, h.backend.URL()+"/api/v2/slack/message-action")

	go func() {
		assertDBNoError(h.t, h.backend.Run(context.Background()), "run backend") // cannot fail immediately from a background goroutine
	}()
	err = h.backend.WaitForStartup(ctx)
	requireDBNoError(h.t, err, "start backend")

	h.t.Logf("Backend restarted")
}

// URL returns the backend server's URL
func (h *Harness) URL() string {
	return h.backend.URL()
}

// SendMail will send an email to the backend's SMTP server.
func (h *Harness) SendMail(from, to, subject, body string) {
	h.t.Helper()

	err := smtp.SendMail(h.App().SMTPAddr(), nil, from, []string{to}, []byte(fmt.Sprintf("Subject: %s\r\n\r\n%s", subject, body)))
	require.NoError(h.t, err)
}

// Migrate will perform `steps` number of migrations.
func (h *Harness) Migrate(migrationName string) {
	h.t.Helper()
	h.t.Logf("Running migrations (target: %s)", migrationName)
	l := log.NewLogger()
	l.ErrorsOnly()
	// Migration failures are reported through the credential-safe diagnostic below.
	l.SetOutput(io.Discard)
	_, err := migrate.Up(log.WithLogger(context.Background(), l), h.dbURL, migrationName)
	requireDBNoError(h.t, err, "run migration")
}

// IgnoreErrorsWith will cause the Harness to ignore backend errors containing the specified substring.
func (h *Harness) IgnoreErrorsWith(substr string) {
	h.mx.Lock()
	defer h.mx.Unlock()
	h.ignoreErrors = append(h.ignoreErrors, substr)
}

// Now returns the current time, as observed by the DB.
func (h *Harness) Now() time.Time {
	h.t.Helper()

	var now time.Time
	err := h.appPool.QueryRow(context.Background(), "SELECT NOW()").Scan(&now)
	requireDBNoError(h.t, err, "get now()")

	return now
}

// FastForwardToTime will fast-forward the database time to the next occurrence of the provided clock time.
func (h *Harness) FastForwardToTime(t timeutil.Clock, zoneName string) {
	h.t.Helper()

	zone, err := time.LoadLocation(zoneName)
	require.NoError(h.t, err, "load location")

	now := h.Now()

	y, m, d := now.In(zone).Date()
	dst := time.Date(y, m, d, t.Hour(), t.Minute(), 0, 0, zone)
	if !dst.After(now) {
		dst = dst.AddDate(0, 0, 1)
	}

	h.FastForward(dst.Sub(now))
}

func (h *Harness) FastForward(d time.Duration) {
	h.t.Helper()
	h.t.Logf("Fast-forward %s", d.String())
	err := h.pgTime.AdvanceTime(context.Background(), d)
	requireDBNoError(h.t, err, "fast-forward time")
}

func (h *Harness) execQuery(sql string, data interface{}) {
	h.t.Helper()
	t := template.New("sql")
	t.Funcs(template.FuncMap{
		"uuidJSON":            func(id string) string { return fmt.Sprintf(`"%s"`, h.uuidG.Get(id)) },
		"uuid":                func(id string) string { return fmt.Sprintf("'%s'", h.uuidG.Get(id)) },
		"smokeOrganizationID": func() string { return fmt.Sprintf("'%s'", SmokeOrganizationID) },
		"phone":               func(id string) string { return fmt.Sprintf("'%s'", h.phoneCCG.Get(id)) },
		"email":               func(id string) string { return fmt.Sprintf("'%s'", h.emailG.Get(id)) },
		"phoneCC":             func(cc, id string) string { return fmt.Sprintf("'%s'", h.phoneCCG.GetWithArg(cc, id)) },
		"slackChannelID":      func(name string) string { return fmt.Sprintf("'%s'", h.Slack().Channel(name).ID()) },
		"slackUserID":         func(name string) string { return fmt.Sprintf("'%s'", h.Slack().User(name).ID()) },
		"slackTeamID":         func() string { return fmt.Sprintf("'%s'", h.slackApp.TeamID) },
		"slackUserGroupID":    func(name string) string { return fmt.Sprintf("'%s'", h.Slack().UserGroup(name).ID()) },
	})
	_, err := t.Parse(sql)
	if err != nil {
		h.t.Fatalf("failed to parse query template: %v", err)
	}

	b := new(bytes.Buffer)
	err = t.Execute(b, data)
	if err != nil {
		h.t.Fatalf("failed to render query template: %v", err)
	}

	err = ExecSQLBatch(context.Background(), h.dbURL, b.String())
	requireDBNoError(h.t, err, "exec query")
}

// CreateAlerts will create one or more unacknowledged alerts for a service.
func (h *Harness) CreateAlert(serviceID string, summary string) TestAlert {
	h.t.Helper()

	return h.CreateAlertWithDetails(serviceID, summary, "")
}

type TestAlert interface {
	ID() int
	Ack()
	Escalate()
	Close()
}
type testAlert struct {
	h *Harness
	a alert.Alert
}

func (t testAlert) setStatus(stat alert.Status) {
	t.h.t.Helper()
	permission.SudoContext(context.Background(), func(ctx context.Context) {
		t.h.t.Helper()
		tx, err := t.h.backend.DB().BeginTx(ctx, nil)
		requireDBNoError(t.h.t, err, "begin tx")
		defer SQLRollback(t.h.t, "harness: set alert status", tx)

		t.a.Status = stat

		result, isNew, err := t.h.backend.AlertStore.CreateOrUpdateTx(ctx, tx, &t.a)
		requireDBNoError(t.h.t, err, "set alert status")
		require.False(t.h.t, isNew, "not be new")
		require.NotNil(t.h.t, result)

		requireDBNoError(t.h.t, tx.Commit(), "commit tx")
	})
}

func (t testAlert) ID() int { return t.a.ID }
func (t testAlert) Close()  { t.setStatus(alert.StatusClosed) }
func (t testAlert) Ack()    { t.setStatus(alert.StatusActive) }
func (t testAlert) Escalate() {
	t.h.t.Helper()
	permission.SudoContext(context.Background(), func(ctx context.Context) {
		t.h.t.Helper()

		err := t.h.backend.AlertStore.Escalate(ctx, t.a.ID, 0)
		requireDBNoError(t.h.t, err, "escalate alert")
	})
}

// CreateAlertWithDetails will create a single alert with summary and detailss.
func (h *Harness) CreateAlertWithDetails(serviceID, summary, details string) TestAlert {
	h.t.Helper()

	var newAlert alert.Alert
	permission.SudoContext(context.Background(), func(ctx context.Context) {
		h.t.Helper()
		tx, err := h.backend.DB().BeginTx(ctx, nil)
		requireDBNoError(h.t, err, "start tx")
		defer SQLRollback(h.t, "harness: create alert", tx)

		a := &alert.Alert{
			ServiceID: serviceID,
			Summary:   summary,
			Details:   details,
		}

		h.t.Logf("insert alert: %v", a)
		_newAlert, isNew, err := h.backend.AlertStore.CreateOrUpdateTx(ctx, tx, a)
		requireDBNoError(h.t, err, "insert alert")
		if !isNew {
			h.t.Fatal("could not create duplicate alert with summary: " + summary)
		}
		newAlert = *_newAlert

		err = tx.Commit()
		requireDBNoError(h.t, err, "commit tx")
	})

	return testAlert{h: h, a: newAlert}
}

// AddNotificationRule will add a notification rule to the database.
func (h *Harness) AddNotificationRule(userID, cmID string, delayMinutes int) {
	h.t.Helper()
	nr := &notificationrule.NotificationRule{
		DelayMinutes:    delayMinutes,
		UserID:          userID,
		ContactMethodID: uuid.MustParse(cmID),
	}
	h.t.Logf("insert notification rule: %v", nr)
	permission.SudoContext(context.Background(), func(ctx context.Context) {
		h.t.Helper()
		_, err := h.backend.NotificationRuleStore.Insert(ctx, nr)
		requireDBNoError(h.t, err, "insert notification rule")
	})
}

// Trigger will trigger, and wait for, an engine cycle.
func (h *Harness) Trigger() {
	id := h.backend.Engine.NextCycleID()
	go h.backend.Engine.Trigger()
	requireDBNoError(h.t, h.backend.Engine.WaitCycleID(context.Background(), id), "wait for engine cycle")
}

// Escalate will escalate an alert in the database, when 'level' matches.
func (h *Harness) Escalate(alertID, level int) {
	h.t.Helper()
	err := h.EscalateAlertErr(alertID)
	requireDBNoError(h.t, err, "escalate alert")
}

func (h *Harness) EscalateAlertErr(alertID int) (err error) {
	h.t.Helper()
	h.t.Logf("escalate alert #%d", alertID)
	permission.SudoContext(context.Background(), func(ctx context.Context) {
		h.t.Helper()
		err = h.backend.AlertStore.Escalate(ctx, alertID, -1)
	})
	return err
}

// Phone will return the generated phone number for the id provided.
func (h *Harness) Phone(id string) string { return h.phoneCCG.Get(id) }

// PhoneCC will return the generated phone number for the id provided.
func (h *Harness) PhoneCC(cc, id string) string { return h.phoneCCG.GetWithArg(cc, id) }

// UUID will return the generated UUID for the id provided.
func (h *Harness) UUID(id string) string { return h.uuidG.Get(id) }

func (h *Harness) isClosing() bool {
	h.mx.Lock()
	defer h.mx.Unlock()
	return h.closing
}

func (h *Harness) dumpDB() {
	testName := reflect.ValueOf(h.t).Elem().FieldByName("name").String()
	file := filepath.Join("smoketest_db_dump", testName+".sql")
	file, err := filepath.Abs(file)
	if err != nil {
		h.t.Fatalf("failed to get abs dump path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		h.t.Fatalf("failed to create abs dump path: %v", err)
	}

	conn, err := pgx.Connect(context.Background(), h.dbURL)
	requireDBNoError(h.t, err, "connect to dump database")
	defer conn.Close(context.Background())

	var t time.Time
	err = conn.QueryRow(context.Background(), "select now()").Scan(&t)
	requireDBNoError(h.t, err, "read dump timestamp")

	fd, err := os.Create(file)
	if err != nil {
		h.t.Fatalf("failed to open dump file: %v", err)
	}
	defer fd.Close()

	err = pgdump.DumpData(context.Background(), conn, fd, nil)
	assertDBNoError(h.t, err, "dump database")

	_, err = fmt.Fprintf(fd, "\n-- Last Timestamp: %s\n", t.Format(time.RFC3339Nano))
	if err != nil {
		h.t.Fatalf("failed to open DB dump: %v", err)
	}
}

// Close terminates any background processes, and drops the testing database.
// It should be called at the end of all tests (usually with `defer h.Close()`).
func (h *Harness) Close() {
	h.t.Helper()
	if recErr := recover(); recErr != nil {
		defer panic(recErr)
	}

	// Deferred so it still runs if a later WaitAndAssert or Shutdown call
	// triggers Goexit (e.g. via t.Fatalf). Closes the log pipe writer and
	// blocks until watchBackendLogs has drained, preventing it from calling
	// t.Logf after the test has been marked complete.
	defer func() {
		h.mx.Lock()
		h.closing = true
		h.mx.Unlock()
		if h.backendLogs != nil {
			h.backendLogs.Close()
		}
		if h.logsDone != nil {
			<-h.logsDone
		}
	}()

	h.dumpDB() // early as possible

	// If backend startup never completed, Engine is nil and Trigger would panic;
	// skip assertions that depend on driving engine cycles.
	if h.backend != nil && h.backend.Engine != nil {
		h.tw.WaitAndAssert(h.t)
		h.slack.WaitAndAssert()
		h.email.WaitAndAssert()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := h.backend.Shutdown(ctx)
	assertDBNoError(h.t, err, "shutdown backend cleanly")

	h.slackS.Close()
	h.twS.Close()

	h.tw.Close()

	h.pgTime.Close()

	h.appPool.Close()

	conn, err := pgx.Connect(ctx, DBURL(""))
	assertDBNoError(h.t, err, "connect to drop database")
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, "drop database "+sqlutil.QuoteID(h.dbName))
	assertDBNoError(h.t, err, "drop database")
}

// SetCarrierName will set the carrier name for the given phone number.
func (h *Harness) SetCarrierName(number, name string) {
	h.tw.SetCarrierInfo(number, twilio.CarrierInfo{Name: name})
}

// TwilioNumber will return a registered (or register if missing) Twilio number for the given ID.
// The default FromNumber will always be the empty ID.
func (h *Harness) TwilioNumber(id string) string {
	if id != "" {
		id = ":" + id
	}
	num := h.phoneCCG.Get("twilio" + id)

	err := h.tw.RegisterSMSCallback(num, h.URL()+"/v1/twilio/sms/messages")
	if err != nil {
		h.t.Fatalf("failed to init twilio (SMS callback): %v", err)
	}
	err = h.tw.RegisterVoiceCallback(num, h.URL()+"/v1/twilio/voice/call")
	if err != nil {
		h.t.Fatalf("failed to init twilio (voice callback): %v", err)
	}

	return num
}

// TwilioMessagingService will return the id and phone numbers for the mock messaging service.
func (h *Harness) TwilioMessagingService() string {
	h.mx.Lock()
	if h.msgSvcID != "" {
		h.mx.Unlock()
		return h.msgSvcID
	}
	defer h.mx.Unlock()

	nums := []string{h.phoneCCG.Get("twilio:sid1"), h.phoneCCG.Get("twilio:sid2"), h.phoneCCG.Get("twilio:sid3")}
	newID, err := h.tw.NewMessagingService(h.URL()+"/v1/twilio/sms/messages", nums...)
	if err != nil {
		panic(err)
	}

	h.msgSvcID = newID
	return newID
}

// TwilioMessagingServiceRCS will return the id and phone numbers for the mock messaging service with RCS enabled.
func (h *Harness) TwilioMessagingServiceRCS() (rcs, msg string) {
	h.mx.Lock()
	defer h.mx.Unlock()
	if h.rcsSenderID != "" {
		return h.rcsSenderID, h.rcsMsgSvcID
	}

	nums := []string{h.phoneCCG.Get("twilio:rcs:sid1"), h.phoneCCG.Get("twilio:rcs:sid2"), h.phoneCCG.Get("twilio:rcs:sid3")}
	newID, err := h.tw.NewMessagingService(h.URL()+"/v1/twilio/sms/messages", nums...)
	if err != nil {
		panic(err)
	}

	h.rcsMsgSvcID = newID

	rcsID, err := h.tw.EnableRCS(newID)
	require.NoError(h.t, err)
	h.rcsSenderID = rcsID

	return rcsID, newID
}

// CreateUser generates a random user.
func (h *Harness) CreateUser() (u *user.User) {
	h.t.Helper()
	var err error
	permission.SudoContext(context.Background(), func(ctx context.Context) {
		u, err = h.backend.UserStore.Insert(ctx, &user.User{
			Name:  fmt.Sprintf("Generated%d", h.userGeneratedIndex),
			ID:    uuid.New().String(),
			Role:  permission.RoleUser,
			Email: fmt.Sprintf("generated%d@example.com", h.userGeneratedIndex),
		})
	})
	requireDBNoError(h.t, err, "generate random user")
	h.userGeneratedIndex++
	return u
}

// WaitAndAssertOnCallUsers will ensure the correct set of users as on-call for the given serviceID.
func (h *Harness) WaitAndAssertOnCallUsers(serviceID string, userIDs ...string) {
	h.t.Helper()
	doQL := func(query string, res interface{}) {
		g := h.GraphQLQuery2(query)
		for _, err := range g.Errors {
			h.t.Error("GraphQL Error:", err.Message)
		}
		if len(g.Errors) > 0 {
			h.t.Fatal("errors returned from GraphQL")
		}
		if res == nil {
			return
		}
		err := json.Unmarshal(g.Data, &res)
		if err != nil {
			h.t.Fatal("failed to parse response:", err)
		}
	}

	getUsers := func() []string {
		var result struct {
			Service struct {
				OnCallUsers []struct {
					UserID   string
					UserName string
				}
			}
		}

		doQL(fmt.Sprintf(`
			query{
				service(id: "%s"){
					onCallUsers{
						userID
						userName
					}
				}
			}
		`, serviceID), &result)

		var ids []string
		for _, oc := range result.Service.OnCallUsers {
			ids = append(ids, oc.UserID)
		}
		if len(ids) == 0 {
			return nil
		}
		sort.Strings(ids)
		uniq := ids[:1]
		last := ids[0]
		for _, id := range ids[1:] {
			if id == last {
				continue
			}
			uniq = append(uniq, id)
			last = id
		}
		return uniq
	}
	sort.Strings(userIDs)
	check := func(t *assert.CollectT) {
		ids := getUsers()
		require.Lenf(t, ids, len(userIDs), "number of on-call users")
		require.ElementsMatch(t, userIDs, ids, "on-call users")
	}
	h.Trigger() // run engine cycle

	assert.EventuallyWithT(h.t, check, 15*time.Second, time.Second)
}
