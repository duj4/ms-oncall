package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/notification/nfydest"
	"github.com/target/goalert/notificationchannel"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/validation"
)

const scheduleDataOrganizationSQL = `
INSERT INTO organizations (id, classification, display_name, canonical_name)
VALUES ({{uuid "org-b"}}, 'NORMAL', 'Schedule Data B', 'schedule-data.b');
INSERT INTO normal_organizations (organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
VALUES ({{uuid "org-b"}}, 'NORMAL', 'schedule-data:b', 'Etc/UTC');
INSERT INTO users (id, name, email, role)
VALUES ({{uuid "user-a"}}, 'Schedule Data User', '', 'user'),
       ({{uuid "user-b"}}, 'Schedule Data Foreign User', '', 'user');
INSERT INTO user_organization_assignments (
 user_id, effective_organization_id, effective_organization_classification,
 effective_normal_organization_id, organization_role, mapping_outcome,
 authoritative_evaluated_at, source_config_version, matched_count
) VALUES ({{uuid "user-b"}}, {{uuid "org-b"}}, 'NORMAL', {{uuid "org-b"}},
 'ORG_MEMBER', 'EXACTLY_ONE', now(), 'schedule-data-test', 1);
INSERT INTO schedules (id, organization_id, name, time_zone)
VALUES ({{uuid "own"}}, {{smokeOrganizationID}}, 'Schedule Data A', 'Etc/UTC'),
       ({{uuid "foreign"}}, {{uuid "org-b"}}, 'Schedule Data B', 'Etc/UTC');
`

var scheduleDataOperations = []string{"set", "set-clear", "clear", "rules"}

func scheduleDataHarness(t *testing.T) *harness.Harness {
	t.Helper()
	h := harness.NewHarness(t, scheduleDataOrganizationSQL, "")
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	return h
}

func scheduleDataContext(t *testing.T) context.Context {
	t.Helper()
	return permission.SystemContext(scheduleDataRequestContext(t), "Smoketest")
}

func scheduleDataRequestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func scheduleDataTemp(h *harness.Harness) schedule.TemporarySchedule {
	start := time.Date(2090, 1, 1, 0, 0, 0, 0, time.UTC)
	return schedule.TemporarySchedule{Start: start, End: start.Add(4 * time.Hour), Shifts: []schedule.FixedShift{
		{Start: start, End: start.Add(4 * time.Hour), UserID: h.UUID("user-a")},
	}}
}

// The four entry points intentionally share the same fixture and assertions.
func scheduleDataMutate(ctx context.Context, s *schedule.Store, tx *sql.Tx, id uuid.UUID, temp schedule.TemporarySchedule, op string, org *uuid.UUID) error {
	switch op {
	case "set":
		return s.SetTemporaryScheduleScoped(ctx, tx, id, temp, org)
	case "set-clear":
		return s.SetClearTemporaryScheduleScoped(ctx, tx, id, temp, temp.Start, temp.End, org)
	case "clear":
		return s.ClearTemporarySchedulesScoped(ctx, tx, id, temp.Start, temp.End, org)
	case "rules":
		return s.SetOnCallNotificationRulesScoped(ctx, tx, id, nil, org)
	default:
		panic("unknown schedule data operation")
	}
}

func scheduleDataUnscoped(ctx context.Context, s *schedule.Store, tx *sql.Tx, id uuid.UUID, temp schedule.TemporarySchedule, op string) error {
	switch op {
	case "set":
		return s.SetTemporarySchedule(ctx, tx, id, temp)
	case "set-clear":
		return s.SetClearTemporarySchedule(ctx, tx, id, temp, temp.Start, temp.End)
	case "clear":
		return s.ClearTemporarySchedules(ctx, tx, id, temp.Start, temp.End)
	case "rules":
		return s.SetOnCallNotificationRules(ctx, tx, id, nil)
	default:
		panic("unknown schedule data operation")
	}
}

func scheduleDataReset(t *testing.T, h *harness.Harness, parent, raw string) {
	t.Helper()
	_, err := h.App().DB().Exec(`DELETE FROM schedule_data WHERE schedule_id=$1`, h.UUID(parent))
	require.NoError(t, err)
	if raw != "" {
		_, err = h.App().DB().Exec(`INSERT INTO schedule_data(schedule_id,data) VALUES($1,$2)`, h.UUID(parent), raw)
		require.NoError(t, err)
	}
}

func scheduleDataRaw(t *testing.T, h *harness.Harness, parent string) string {
	t.Helper()
	var raw string
	err := h.App().DB().QueryRow(`SELECT data::text FROM schedule_data WHERE schedule_id=$1`, h.UUID(parent)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ""
	}
	require.NoError(t, err)
	return raw
}

// Stable observations support rerunning the same cases against the exact base.
// SQL errors record SQLSTATE only, never connection strings or destinations.
func scheduleDataOutcome(err error) string {
	if err == nil {
		return "OK"
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return "SQLSTATE " + pg.Code
	}
	return err.Error()
}

func scheduleDataRecord(t *testing.T, outcome any) {
	t.Helper()
	data, err := json.Marshal(struct {
		Case    string `json:"case"`
		Outcome any    `json:"outcome"`
	}{t.Name(), outcome})
	require.NoError(t, err)
	t.Log("SCHEDULE_DATA_CASE " + string(data))
}

func scheduleDataUnavailable(t *testing.T, err error) {
	t.Helper()
	var field validation.FieldError
	require.ErrorAs(t, err, &field)
	require.Equal(t, "ScheduleID", field.Field())
	require.Equal(t, "schedule does not exist", field.Reason())
}

func TestScheduleDataOrganizationStore(t *testing.T) {
	h := scheduleDataHarness(t)
	org := uuid.MustParse(harness.SmokeOrganizationID)
	for _, op := range scheduleDataOperations {
		for _, tc := range []struct{ name, parent, raw string }{
			{"own-existing", "own", `{}`}, {"own-first-write", "own", ""},
			{"foreign-existing", "foreign", `{}`}, {"foreign-absent", "foreign", ""},
			{"foreign-malformed", "foreign", `{"V1":{"TemporarySchedules":"not-an-array"}}`},
			{"missing", "missing", ""},
		} {
			t.Run(op+"/"+tc.name, func(t *testing.T) {
				scheduleDataReset(t, h, tc.parent, tc.raw)
				before := scheduleDataRaw(t, h, tc.parent)
				err := scheduleDataMutate(scheduleDataContext(t), h.App().ScheduleStore, nil, uuid.MustParse(h.UUID(tc.parent)), scheduleDataTemp(h), op, &org)
				scheduleDataRecord(t, scheduleDataOutcome(err))
				if tc.parent == "own" {
					require.NoError(t, err)
					require.NotEmpty(t, scheduleDataRaw(t, h, tc.parent))
				} else {
					scheduleDataUnavailable(t, err)
					require.Equal(t, before, scheduleDataRaw(t, h, tc.parent))
				}
			})
		}
		for _, mode := range []string{"wrapper", "nil-scope", "zero-scope"} {
			t.Run(op+"/"+mode, func(t *testing.T) {
				scheduleDataReset(t, h, "foreign", "")
				id, ctx := uuid.MustParse(h.UUID("foreign")), scheduleDataContext(t)
				var err error
				switch mode {
				case "wrapper":
					err = scheduleDataUnscoped(ctx, h.App().ScheduleStore, nil, id, scheduleDataTemp(h), op)
				case "nil-scope":
					err = scheduleDataMutate(ctx, h.App().ScheduleStore, nil, id, scheduleDataTemp(h), op, nil)
				default:
					zero := uuid.Nil
					err = scheduleDataMutate(ctx, h.App().ScheduleStore, nil, id, scheduleDataTemp(h), op, &zero)
				}
				scheduleDataRecord(t, scheduleDataOutcome(err))
				if mode == "zero-scope" {
					require.EqualError(t, err, "invalid value for 'OrganizationID': must be specified")
					require.Empty(t, scheduleDataRaw(t, h, "foreign"))
				} else {
					require.NoError(t, err)
					require.NotEmpty(t, scheduleDataRaw(t, h, "foreign"))
				}
			})
		}
	}
	for _, op := range []string{"set", "set-clear"} {
		t.Run(op+"/global-user-existence", func(t *testing.T) {
			temp := scheduleDataTemp(h)
			temp.Shifts[0].UserID = h.UUID("user-b")
			err := scheduleDataMutate(scheduleDataContext(t), h.App().ScheduleStore, nil, uuid.MustParse(h.UUID("own")), temp, op, &org)
			scheduleDataRecord(t, scheduleDataOutcome(err))
			require.NoError(t, err, "this slice does not add User Organization affiliation")
		})
	}
}

func scheduleDataHuman(t *testing.T, h *harness.Harness, role permission.Role) context.Context {
	t.Helper()
	_, err := h.App().DB().Exec(`UPDATE users SET role=$2 WHERE id=$1`, h.UUID("user-a"), role)
	require.NoError(t, err)
	session := uuid.NewString()
	ctx := permission.UserSourceContext(scheduleDataRequestContext(t), h.UUID("user-a"), role, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session})
	r, err := auth.NewRequester(h.UUID("user-a"), session)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, r)
	c, err := executioncontext.NewHumanExecutionContextConstructor(h.App().OrganizationStore)
	require.NoError(t, err)
	authority, err := c.Construct(ctx)
	require.NoError(t, err)
	return executioncontext.WithExecutionContext(ctx, authority)
}

func scheduleDataApp(h *harness.Harness) *graphqlapp.App {
	return &graphqlapp.App{DB: h.App().DB(), ScheduleStore: h.App().ScheduleStore, NCStore: h.App().NCStore, DestReg: h.App().DestRegistry}
}

func scheduleDataGraphQL(ctx context.Context, app *graphqlapp.App, id string, temp schedule.TemporarySchedule, op string) error {
	var err error
	switch op {
	case "set", "set-clear":
		input := graphql2.SetTemporaryScheduleInput{ScheduleID: id, Start: temp.Start, End: temp.End, Shifts: temp.Shifts}
		if op == "set-clear" {
			input.ClearStart, input.ClearEnd = &temp.Start, &temp.End
		}
		_, err = app.Mutation().SetTemporarySchedule(ctx, input)
	case "clear":
		_, err = app.Mutation().ClearTemporarySchedules(ctx, graphql2.ClearTemporarySchedulesInput{ScheduleID: id, Start: temp.Start, End: temp.End})
	case "rules":
		_, err = app.Mutation().SetScheduleOnCallNotificationRules(ctx, graphql2.SetScheduleOnCallNotificationRulesInput{ScheduleID: id})
	default:
		panic("unknown schedule data operation")
	}
	return err
}

func TestScheduleDataOrganizationGraphQL(t *testing.T) {
	h := scheduleDataHarness(t)
	for _, role := range []permission.Role{permission.RoleUser, permission.RoleAdmin} {
		ctx := scheduleDataHuman(t, h, role)
		for _, op := range scheduleDataOperations {
			for _, parent := range []string{"own", "foreign", "missing"} {
				t.Run(string(role)+"/"+op+"/"+parent, func(t *testing.T) {
					scheduleDataReset(t, h, parent, "")
					err := scheduleDataGraphQL(ctx, scheduleDataApp(h), h.UUID(parent), scheduleDataTemp(h), op)
					scheduleDataRecord(t, scheduleDataOutcome(err))
					if parent == "own" {
						require.NoError(t, err)
					} else {
						scheduleDataUnavailable(t, err)
						require.Empty(t, scheduleDataRaw(t, h, parent))
					}
				})
			}
		}
	}
	api := permission.UserSourceContext(scheduleDataRequestContext(t), h.UUID("user-a"), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()})
	for _, op := range scheduleDataOperations {
		t.Run("API-key/"+op, func(t *testing.T) {
			err := scheduleDataGraphQL(api, scheduleDataApp(h), h.UUID("foreign"), scheduleDataTemp(h), op)
			scheduleDataRecord(t, scheduleDataOutcome(err))
			require.NoError(t, err)
		})
	}
}

func TestScheduleDataOrganizationInvalidHuman(t *testing.T) {
	h := scheduleDataHarness(t)
	valid := scheduleDataHuman(t, h, permission.RoleUser)
	r := auth.RequesterFromContext(valid)
	legacy := permission.UserSourceContext(scheduleDataRequestContext(t), r.UserID().String(), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: r.SessionID().String()})
	contexts := map[string]context.Context{
		"missing-requester":    legacy,
		"missing-authority":    auth.WithRequester(legacy, *r),
		"zero-authority":       executioncontext.WithExecutionContext(auth.WithRequester(legacy, *r), executioncontext.ExecutionContext{}),
		"inconsistent-session": permission.UserSourceContext(valid, r.UserID().String(), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}),
		"inconsistent-source":  permission.UserSourceContext(valid, r.UserID().String(), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: r.SessionID().String()}),
		"inconsistent-actor":   permission.UserSourceContext(valid, uuid.NewString(), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: r.SessionID().String()}),
	}
	other, err := auth.NewRequester(uuid.NewString(), r.SessionID().String())
	require.NoError(t, err)
	contexts["inconsistent-authority-actor"] = auth.WithRequester(permission.UserSourceContext(valid, other.UserID().String(), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: r.SessionID().String()}), other)
	for name, ctx := range contexts {
		for _, op := range scheduleDataOperations {
			t.Run(name+"/"+op, func(t *testing.T) {
				before := scheduleDataRaw(t, h, "own")
				err := scheduleDataGraphQL(ctx, scheduleDataApp(h), h.UUID("own"), scheduleDataTemp(h), op)
				scheduleDataRecord(t, scheduleDataOutcome(err))
				require.True(t, permission.IsPermissionError(err))
				require.Equal(t, before, scheduleDataRaw(t, h, "own"))
			})
		}
	}
	t.Run("zero-organization-assignment", func(t *testing.T) {
		// The canonical persistence contract cannot admit a zero Organization.
		// No unsafe forging of ExecutionContext's private representation is used.
		_, err := h.App().DB().Exec(`UPDATE user_organization_assignments SET
		 effective_organization_id=$2, effective_normal_organization_id=$2 WHERE user_id=$1`, h.UUID("user-a"), uuid.Nil)
		scheduleDataRecord(t, scheduleDataOutcome(err))
		require.Equal(t, "SQLSTATE 23514", scheduleDataOutcome(err))
		var organizationID uuid.UUID
		require.NoError(t, h.App().DB().QueryRow(`SELECT effective_organization_id FROM user_organization_assignments WHERE user_id=$1`, h.UUID("user-a")).Scan(&organizationID))
		require.Equal(t, uuid.MustParse(harness.SmokeOrganizationID), organizationID)
	})
	// Public construction cannot create a Default/zero/non-operational carrier.
	// Verify those admissions fail, then ensure no nil-scope fallback occurs.
	for _, state := range []string{"Default", "missing-assignment"} {
		if state == "Default" {
			_, err = h.App().DB().Exec(`UPDATE user_organization_assignments SET effective_organization_id=$2,
			 effective_organization_classification='DEFAULT', effective_normal_organization_id=NULL,
			 organization_role='NONE', mapping_outcome='ZERO', matched_count=0 WHERE user_id=$1`, h.UUID("user-a"), organization.DefaultOrganizationID)
		} else {
			_, err = h.App().DB().Exec(`DELETE FROM user_organization_assignments WHERE user_id=$1`, h.UUID("user-a"))
		}
		require.NoError(t, err)
		constructor, err := executioncontext.NewHumanExecutionContextConstructor(h.App().OrganizationStore)
		require.NoError(t, err)
		ctx := auth.WithRequester(legacy, *r)
		value, err := constructor.Construct(ctx)
		require.Error(t, err)
		require.False(t, value.Valid())
		for _, op := range scheduleDataOperations {
			t.Run(state+"/"+op, func(t *testing.T) {
				err := scheduleDataGraphQL(executioncontext.WithExecutionContext(ctx, value), scheduleDataApp(h), h.UUID("own"), scheduleDataTemp(h), op)
				scheduleDataRecord(t, scheduleDataOutcome(err))
				require.True(t, permission.IsPermissionError(err))
			})
		}
	}
}

// A local provider exercises real Registry and MapDestToID behavior without
// sending notifications or using a network/provider credential.
type scheduleDataProvider struct {
	capable bool
	label   string
	calls   int
}

func (*scheduleDataProvider) ID() string { return "schedule-data-test" }
func (p *scheduleDataProvider) TypeInfo(context.Context) (*nfydest.TypeInfo, error) {
	return &nfydest.TypeInfo{Enabled: true, SupportsOnCallNotify: p.capable, RequiredFields: []nfydest.FieldConfig{{FieldID: "id"}}}, nil
}
func (*scheduleDataProvider) ValidateField(_ context.Context, _, value string) error {
	if value == "" {
		return validation.NewFieldError("id", "required")
	}
	return nil
}
func (p *scheduleDataProvider) DisplayInfo(context.Context, map[string]string) (*nfydest.DisplayInfo, error) {
	p.calls++
	return &nfydest.DisplayInfo{Text: p.label}, nil
}

func scheduleDataProviderApp(t *testing.T, h *harness.Harness) (*graphqlapp.App, *scheduleDataProvider) {
	t.Helper()
	app := scheduleDataApp(h)
	p := &scheduleDataProvider{capable: true, label: "new display name"}
	app.DestReg = nfydest.NewRegistry()
	app.DestReg.RegisterProvider(context.Background(), p)
	var err error
	app.NCStore, err = notificationchannel.NewStore(context.Background(), app.DB, app.DestReg)
	require.NoError(t, err)
	return app, p
}

func TestScheduleDataOrganizationDestinationRollback(t *testing.T) {
	h := scheduleDataHarness(t)
	ctx := scheduleDataHuman(t, h, permission.RoleUser)
	app, provider := scheduleDataProviderApp(t, h)
	for _, parent := range []string{"own", "foreign", "missing"} {
		for _, mode := range []string{"insert", "update"} {
			t.Run(parent+"/"+mode, func(t *testing.T) {
				dest := gadb.NewDestV1(provider.ID(), "id", parent+mode)
				if mode == "update" {
					_, err := app.DB.Exec(`INSERT INTO notification_channels(id,dest,name) VALUES($1,$2,'original display name')`, uuid.New(), gadb.NullDestV1{Valid: true, DestV1: dest})
					require.NoError(t, err)
				}
				calls := provider.calls
				_, err := app.Mutation().SetScheduleOnCallNotificationRules(ctx, graphql2.SetScheduleOnCallNotificationRulesInput{ScheduleID: h.UUID(parent), Rules: []graphql2.OnCallNotificationRuleInput{{Dest: dest}}})
				scheduleDataRecord(t, scheduleDataOutcome(err))
				require.Greater(t, provider.calls, calls, "destination mapping still precedes parent authorization")
				var name string
				lookup := app.DB.QueryRow(`SELECT name FROM notification_channels WHERE dest=$1`, gadb.NullDestV1{Valid: true, DestV1: dest}).Scan(&name)
				if parent == "own" {
					require.NoError(t, err)
					require.NoError(t, lookup)
					require.Equal(t, provider.label, name)
				} else {
					scheduleDataUnavailable(t, err)
					if mode == "insert" {
						require.ErrorIs(t, lookup, sql.ErrNoRows)
					} else {
						require.NoError(t, lookup)
						require.Equal(t, "original display name", name)
					}
				}
			})
		}
	}
}

func TestScheduleDataOrganizationOuterTransaction(t *testing.T) {
	h := scheduleDataHarness(t)
	org := uuid.MustParse(harness.SmokeOrganizationID)
	for _, op := range scheduleDataOperations {
		t.Run(op, func(t *testing.T) {
			ctx := scheduleDataContext(t)
			scheduleDataReset(t, h, "own", "")
			tx, err := h.App().DB().BeginTx(ctx, nil)
			require.NoError(t, err)
			defer tx.Rollback()
			err = scheduleDataMutate(ctx, h.App().ScheduleStore, tx, uuid.MustParse(h.UUID("own")), scheduleDataTemp(h), op, &org)
			scheduleDataRecord(t, scheduleDataOutcome(err))
			require.NoError(t, err)
			var n int
			require.NoError(t, tx.QueryRowContext(ctx, `SELECT count(*) FROM schedule_data WHERE schedule_id=$1`, h.UUID("own")).Scan(&n))
			require.Equal(t, 1, n)
			require.Empty(t, scheduleDataRaw(t, h, "own"), "Store must not independently commit")
			require.NoError(t, tx.Rollback())
			require.Empty(t, scheduleDataRaw(t, h, "own"))
		})
	}
	t.Run("uncommitted-parent-in-caller-transaction", func(t *testing.T) {
		ctx := scheduleDataContext(t)
		tx, err := h.App().DB().BeginTx(ctx, nil)
		require.NoError(t, err)
		defer tx.Rollback()
		id := uuid.New()
		_, err = tx.ExecContext(ctx, `INSERT INTO schedules(id,organization_id,name,time_zone) VALUES($1,$2,'transaction-local','Etc/UTC')`, id, org)
		require.NoError(t, err)
		err = scheduleDataMutate(ctx, h.App().ScheduleStore, tx, id, scheduleDataTemp(h), "set", &org)
		scheduleDataRecord(t, scheduleDataOutcome(err))
		require.NoError(t, err, "parent authorization must use the supplied transaction")
	})
}
