package migrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/notification/webhook"
	"github.com/target/goalert/notificationchannel"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	audit "github.com/target/goalert/schedule/oncallupdateaudit"
)

func TestOnCall309CanonicalAppend(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.Len(t, h.entries, 309)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-oncall-json-update-audit-d09-contract-impl1\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte{}, h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	require.Equal(t, "6483de5595305db7cbc9895e844fc732ab1c702bdad5d5cc1f811c4e1beb6b13", fmt.Sprintf("%x", sha256.Sum256(prefix)))
	require.Equal(t, int64(309), h.latest().Position)
	require.Equal(t, h.entries[307].ID, h.latest().PredecessorID)
	parsed, err := parseMigrations(h)
	require.NoError(t, err)
	require.False(t, parsed[308].Up.disableTx)
}

func onCallNativeApp(t *testing.T, ctx context.Context, db *sql.DB, f userPhaseAFixture) *graphqlapp.App {
	t.Helper()
	app := updateNativeApp(t, ctx, db)
	app.ScheduleStore = f.schedules
	app.UserStore = f.users
	app.DestReg.RegisterProvider(ctx, webhook.NewSender(ctx, http.DefaultClient))
	var err error
	app.NCStore, err = notificationchannel.NewStore(ctx, db, app.DestReg)
	require.NoError(t, err)
	return app
}

func onCallHTTP(t *testing.T, ctx context.Context, app *graphqlapp.App, wire map[string]any, mutation bool) (*graphql2.UpdateDeletionPreview, []json.RawMessage) {
	t.Helper()
	op, field, selection := "query", "previewSetScheduleOnCallNotificationRules", `{impactVersion complete canProceed requiresConfirmation removed{type id} impacts{relation change policy} onCallJSONUpdate{contractVersion before{ruleID channelID time weekdays} after{ruleID channelID time weekdays} effects{ruleID change source}}}`
	if mutation {
		op, field, selection = "mutation", "setScheduleOnCallNotificationRules", ""
	}
	payload, err := json.Marshal(map[string]any{"query": op + "($input:SetScheduleOnCallNotificationRulesInput!){result:" + field + "(input:$input)" + selection + "}", "variables": map[string]any{"input": wire}})
	require.NoError(t, err)
	var cfg config.Config
	cfg.Webhook.Enable = true
	req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(payload)).WithContext(cfg.Context(ctx))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	var result struct {
		Data   map[string]json.RawMessage
		Errors []json.RawMessage
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	var p *graphql2.UpdateDeletionPreview
	if !mutation && len(result.Errors) == 0 {
		require.NoError(t, json.Unmarshal(result.Data["result"], &p))
	}
	return p, result.Errors
}

func onCallRuleWire(id, dest string, clock string, days []bool) map[string]any {
	r := map[string]any{"dest": map[string]any{"type": webhook.DestTypeWebhook, "args": map[string]string{webhook.FieldWebhookURL: dest}}}
	if id != "" {
		r["id"] = id
	}
	if clock != "" {
		r["time"] = clock
		r["weekdayFilter"] = days
	}
	return r
}

func onCallWire(id uuid.UUID, rules ...map[string]any) map[string]any {
	return map[string]any{"scheduleID": id.String(), "rules": append([]map[string]any{}, rules...)}
}

func onCallInventory(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	var s string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_build_array((SELECT to_jsonb(d) FROM schedule_data d WHERE schedule_id=$1),(SELECT jsonb_agg(to_jsonb(a) ORDER BY event_id) FROM schedule_oncall_update_audit_events a WHERE schedule_id=$1),(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM notification_channels c))::text`, id).Scan(&s))
	return s
}

func onCallSeed(t *testing.T, ctx context.Context, db *sql.DB, app *graphqlapp.App, f userPhaseAFixture) (uuid.UUID, []map[string]any) {
	t.Helper()
	id := f.newSchedule(t, ctx)
	rules := []map[string]any{onCallRuleWire("", "https://oncall-a.test.invalid/", "", nil), onCallRuleWire("", "https://oncall-b.test.invalid/", "09:00", []bool{false, true, true, true, true, true, false})}
	_, errs := onCallHTTP(t, ctx, app, onCallWire(id, rules...), true)
	require.Empty(t, errs)
	for i := range rules {
		rules[i]["id"] = id.String() + ":" + string(rune('0'+i))
	}
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_oncall_update_audit_events WHERE schedule_id=$1`, id))
	return id, rules
}

func TestPostgresOnCall309GraphQL(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "OnCall309Test")
	f := newUserPhaseAFixture(t, ctx, db)
	app := onCallNativeApp(t, ctx, db, f)
	for _, mode := range []string{"remove_one", "clear", "multiple_remove", "channel", "mode_to_timed", "mode_to_change", "time", "weekdays_trim", "weekdays_expand", "equivalent", "reorder", "add", "add_remove", "reuse_id", "omit_id"} {
		t.Run(mode, func(t *testing.T) {
			id, rules := onCallSeed(t, ctx, db, app, f)
			want := true
			switch mode {
			case "remove_one":
				rules = rules[:1]
			case "clear", "multiple_remove":
				rules = rules[:0]
			case "channel":
				rules[0]["dest"] = map[string]any{"type": webhook.DestTypeWebhook, "args": map[string]string{webhook.FieldWebhookURL: "https://new-channel.test.invalid/" + uuid.NewString()}}
			case "mode_to_timed":
				rules[0]["time"] = "10:00"
				rules[0]["weekdayFilter"] = []bool{true, true, true, true, true, true, true}
			case "mode_to_change":
				delete(rules[1], "time")
				delete(rules[1], "weekdayFilter")
			case "time":
				rules[1]["time"] = "10:00"
			case "weekdays_trim":
				rules[1]["weekdayFilter"] = []bool{false, false, true, true, true, true, false}
			case "weekdays_expand":
				rules[1]["weekdayFilter"] = []bool{true, true, true, true, true, true, true}
				want = false
			case "equivalent":
				want = false
			case "reorder":
				rules[0], rules[1] = rules[1], rules[0]
				want = false
			case "add":
				rules = append(rules, onCallRuleWire("", "https://added.test.invalid/", "", nil))
				want = false
			case "add_remove":
				rules = append(rules[:1], onCallRuleWire("", "https://new-and-removed.test.invalid/", "", nil))
			case "reuse_id":
				rules = []map[string]any{onCallRuleWire(id.String()+":0", "https://id-reuse.test.invalid/", "", nil)}
			case "omit_id":
				rules[0], rules[1] = rules[1], rules[0]
				delete(rules[0], "id")
				delete(rules[1], "id")
			}
			wire := onCallWire(id, rules...)
			before := onCallInventory(t, ctx, db, id)
			p, errs := onCallHTTP(t, ctx, app, wire, false)
			require.Empty(t, errs)
			require.True(t, p.Complete)
			require.True(t, p.CanProceed)
			require.Equal(t, want, p.RequiresConfirmation)
			require.Equal(t, before, onCallInventory(t, ctx, db, id), "preview has no writes, including pending Channels")
			if want {
				_, errs = onCallHTTP(t, ctx, app, wire, true)
				require.NotEmpty(t, errs)
				require.Equal(t, before, onCallInventory(t, ctx, db, id))
				wire["confirmation"] = map[string]any{"expectedImpactVersion": p.ImpactVersion, "acknowledgeImpacts": false}
				_, errs = onCallHTTP(t, ctx, app, wire, true)
				require.NotEmpty(t, errs)
				wire["confirmation"] = map[string]any{"expectedImpactVersion": p.ImpactVersion + "x", "acknowledgeImpacts": true}
				_, errs = onCallHTTP(t, ctx, app, wire, true)
				require.NotEmpty(t, errs)
				wire["confirmation"] = scheduleJSONConfirm(p)
			}
			_, errs = onCallHTTP(t, ctx, app, wire, true)
			require.Empty(t, errs)
			var events int
			require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM schedule_oncall_update_audit_events WHERE schedule_id=$1`, id).Scan(&events))
			if mode == "equivalent" || mode == "reorder" {
				require.Equal(t, 1, events)
			} else {
				require.Equal(t, 2, events)
			}
			if want {
				_, errs = onCallHTTP(t, ctx, app, wire, true)
				require.NotEmpty(t, errs, "old consent cannot replay another removal")
			}
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, id))
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1`, id))
		})
	}
}

func TestPostgresOnCall309StoreAndInvalidInput(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "OnCall309Test")
	f := newUserPhaseAFixture(t, ctx, db)
	app := onCallNativeApp(t, ctx, db, f)
	id, rules := onCallSeed(t, ctx, db, app, f)
	before := onCallInventory(t, ctx, db, id)
	for _, scoped := range []bool{false, true} {
		tx := userPhaseATx(t, ctx, db)
		var err error
		if scoped {
			err = f.schedules.SetOnCallNotificationRulesScoped(ctx, tx, id, nil, &f.org)
		} else {
			err = f.schedules.SetOnCallNotificationRules(ctx, tx, id, nil)
		}
		require.Error(t, err)
		require.NoError(t, tx.Commit())
		require.Equal(t, before, onCallInventory(t, ctx, db, id))
	}
	for _, wire := range []map[string]any{
		onCallWire(id, rules[0], rules[0]), onCallWire(id, onCallRuleWire(id.String()+":50", "https://invalid-id.test.invalid/", "", nil)),
		onCallWire(id, onCallRuleWire(uuid.NewString()+":0", "https://invalid-scope.test.invalid/", "", nil)),
		onCallWire(id, map[string]any{}), onCallWire(id, onCallRuleWire("", "invalid-url", "", nil)),
		onCallWire(id, onCallRuleWire("", "https://invalid-time.test.invalid/", "25:00", []bool{true, true, true, true, true, true, true})),
		onCallWire(id, onCallRuleWire("", "https://invalid-days.test.invalid/", "09:00", []bool{false, false, false, false, false, false, false})),
		{"scheduleID": id.String(), "rules": nil}, {"scheduleID": id.String()},
	} {
		_, errs := onCallHTTP(t, ctx, app, wire, false)
		require.NotEmpty(t, errs)
		_, errs = onCallHTTP(t, ctx, app, wire, true)
		require.NotEmpty(t, errs)
		require.Equal(t, before, onCallInventory(t, ctx, db, id))
	}
	// A valid raw Store call cannot persist a nonexistent Channel or widen its
	// capability by reusing another Schedule/transaction identity.
	r := schedule.OnCallNotificationRule{ChannelID: uuid.New()}
	require.Error(t, f.schedules.SetOnCallNotificationRulesScoped(ctx, nil, f.newSchedule(t, ctx), []schedule.OnCallNotificationRule{r}, &f.org))
}

func TestPostgresOnCall309Atomicity(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "OnCall309Test")
	f := newUserPhaseAFixture(t, ctx, db)
	app := onCallNativeApp(t, ctx, db, f)
	id, rules := onCallSeed(t, ctx, db, app, f)
	for _, point := range []string{"json_write", "audit_append", "audit_constraint", "deferred_commit", "actual_write_mismatch", "channel_mapping"} {
		t.Run(point, func(t *testing.T) {
			wire := onCallWire(id, onCallRuleWire(rules[0]["id"].(string), "https://rollback-new.test.invalid/"+uuid.NewString(), "", nil))
			p, errs := onCallHTTP(t, ctx, app, wire, false)
			require.Empty(t, errs)
			wire["confirmation"] = scheduleJSONConfirm(p)
			before := onCallInventory(t, ctx, db, id)
			table, body := "schedule_oncall_update_audit_events", "RAISE EXCEPTION 'synthetic injected fault';"
			if point == "json_write" || point == "actual_write_mismatch" {
				table = "schedule_data"
			}
			if point == "actual_write_mismatch" {
				body = `NEW.data=jsonb_set(NEW.data,'{V1,OnCallNotificationRules}',OLD.data#>'{V1,OnCallNotificationRules}'); RETURN NEW;`
			}
			if point == "channel_mapping" {
				table = "notification_channels"
				body = "NEW.id=gen_random_uuid(); RETURN NEW;"
			}
			if point == "audit_constraint" {
				body = "NEW.effect_count=-1; RETURN NEW;"
			}
			enforcementExec(t, ctx, db, `CREATE FUNCTION oncall309_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+body+` END $$`)
			if point == "deferred_commit" {
				enforcementExec(t, ctx, db, `CREATE CONSTRAINT TRIGGER oncall309_fault AFTER INSERT ON `+table+` DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION oncall309_fault()`)
			} else {
				enforcementExec(t, ctx, db, `CREATE TRIGGER oncall309_fault BEFORE INSERT OR UPDATE ON `+table+` FOR EACH ROW EXECUTE FUNCTION oncall309_fault()`)
			}
			_, errs = onCallHTTP(t, ctx, app, wire, true)
			require.NotEmpty(t, errs)
			enforcementExec(t, ctx, db, `DROP TRIGGER oncall309_fault ON `+table)
			enforcementExec(t, ctx, db, `DROP FUNCTION oncall309_fault()`)
			require.Equal(t, before, onCallInventory(t, ctx, db, id), "JSON, new Channel and success audit roll back together")
		})
	}
}

func TestPostgresOnCall309MigrationAndConstraints(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, 308)
	old := sd6SchemaEvent("schedule")
	u03SchemaAppend(t, db, old)
	historical := u03HistoryRows(t, db)
	n, err := Up(ctx, uri, "")
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, historical, u03HistoryRows(t, db))
	id := uuid.New()
	b := []audit.Rule{{ID: id.String() + ":0", Channel: uuid.NewString(), Time: "09:00", Weekdays: "0111110"}}
	a := []audit.Rule{}
	effects, err := audit.Diff(id, b, a)
	require.NoError(t, err)
	e := audit.Event{Version: 1, EventID: uuid.New(), RequestID: uuid.New(), AttemptID: uuid.New(), ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", ScheduleID: id, OrganizationID: uuid.New(), EnvelopeID: 1, Operation: audit.Operation, OccurredAt: time.Now(), Before: b, After: a, Effects: effects}
	tx := userPhaseATx(t, ctx, db)
	require.NoError(t, audit.Append(ctx, tx, e))
	require.NoError(t, audit.Append(ctx, tx, e))
	require.NoError(t, tx.Commit())
	for name, patch := range map[string]map[string]any{
		"version": {"schema_version": 2}, "root_delete": {"operation": "schedule.delete"}, "legacy": {"operation": "clearTemporarySchedules"}, "root_type": {"root_type": "notification_rule"},
		"scope": {"schedule_id": uuid.NewString()}, "root_org": {"organization_id": uuid.Nil.String()}, "envelope": {"envelope_id": 0},
		"before_missing": {"before_rules": nil}, "after_missing": {"after_rules": nil}, "shape": {"before_rules": map[string]any{}},
		"missing_effect": {"effects": []audit.Effect{}, "effect_count": 0}, "forged_effect": {"effects": []audit.Effect{{RuleID: b[0].ID, Change: "DELETED", Source: "CASCADE"}}}, "count": {"effect_count": 0},
		"duplicate_effect":    {"effects": []audit.Effect{effects[0], effects[0]}, "effect_count": 2},
		"invalid_rule":        {"before_rules": []audit.Rule{{ID: id.String() + ":50", Channel: b[0].Channel}}},
		"bad_channel":         {"before_rules": []audit.Rule{{ID: b[0].ID, Channel: "invalid"}}},
		"bad_time":            {"before_rules": []audit.Rule{{ID: b[0].ID, Channel: b[0].Channel, Time: "24:00", Weekdays: b[0].Weekdays}}},
		"incomplete":          {"before_rules": []map[string]any{{"rule_id": b[0].ID, "channel_id": b[0].Channel}}},
		"extra_private_field": {"before_rules": []map[string]any{{"rule_id": b[0].ID, "channel_id": b[0].Channel, "time": "", "weekdays": "", "destination": "synthetic-forbidden"}}},
	} {
		t.Run(name, func(t *testing.T) {
			patch["event_id"] = uuid.NewString()
			patch["attempt_id"] = uuid.NewString()
			raw, err := json.Marshal(patch)
			require.NoError(t, err)
			tx := userPhaseATx(t, ctx, db)
			_, err = tx.ExecContext(ctx, `INSERT INTO schedule_oncall_update_audit_events SELECT (jsonb_populate_record(NULL::schedule_oncall_update_audit_events,to_jsonb(a)||$2::jsonb)).* FROM schedule_oncall_update_audit_events a WHERE event_id=$1`, e.EventID, raw)
			require.Error(t, err)
			require.NoError(t, tx.Rollback())
		})
	}
	for _, query := range []string{`UPDATE schedule_oncall_update_audit_events SET operation=operation`, `DELETE FROM schedule_oncall_update_audit_events`, `TRUNCATE schedule_oncall_update_audit_events`} {
		tx := userPhaseATx(t, ctx, db)
		_, err := tx.ExecContext(ctx, query)
		require.Error(t, err)
		require.NoError(t, tx.Rollback())
	}
	n, err = Down(ctx, uri, Names()[307])
	require.Error(t, err)
	require.Zero(t, n)
	require.NoError(t, VerifyIsLatest(ctx, uri))
	require.Equal(t, historical, u03HistoryRows(t, db))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_oncall_update_audit_events`))
	// Exercise old appender after the new migration, not just old row reads.
	u03SchemaAppend(t, db, old)
}

// Independent SQL reconstruction must agree for mixed additions/removals,
// channel replacement, mode/time changes and weekday expansion/trimming.
func TestPostgresOnCall309SQLDiffAgreement(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	id := uuid.New()
	rng := rand.New(rand.NewPCG(309, 1))
	for range 120 {
		b, a := []audit.Rule{}, []audit.Rule{}
		for n := range 8 {
			r := audit.Rule{ID: id.String() + ":" + strconv.Itoa(n), Channel: uuid.NewString()}
			if rng.IntN(2) == 1 {
				r.Time = "09:00"
				r.Weekdays = "0111110"
			}
			if rng.IntN(3) != 0 {
				b = append(b, r)
			}
			if rng.IntN(3) == 0 {
				continue
			}
			if rng.IntN(3) == 0 {
				r.Channel = uuid.NewString()
			}
			switch rng.IntN(5) {
			case 0:
				r.Time = ""
				r.Weekdays = ""
			case 1:
				r.Time = "10:00"
				r.Weekdays = "1111111"
			case 2:
				r.Time = "09:00"
				r.Weekdays = "0011111"
			}
			a = append(a, r)
		}
		b, err := audit.Canonical(id, b)
		require.NoError(t, err)
		a, err = audit.Canonical(id, a)
		require.NoError(t, err)
		want, err := audit.Diff(id, b, a)
		require.NoError(t, err)
		before, err := json.Marshal(b)
		require.NoError(t, err)
		after, err := json.Marshal(a)
		require.NoError(t, err)
		var raw []byte
		require.NoError(t, db.QueryRowContext(ctx, `SELECT schedule_oncall_update_rules_diff($1::jsonb,$2::jsonb)`, before, after).Scan(&raw))
		var got []audit.Effect
		require.NoError(t, json.Unmarshal(raw, &got))
		require.Equal(t, want, got)
	}
}

func TestPostgresOnCall309RuleLimit(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "OnCall309Test")
	f := newUserPhaseAFixture(t, ctx, db)
	app := onCallNativeApp(t, ctx, db, f)
	id := f.newSchedule(t, ctx)
	rules := []map[string]any{}
	for n := range 50 {
		rules = append(rules, onCallRuleWire("", fmt.Sprintf("https://limit-%d.test.invalid/", n), "", nil))
	}
	_, errs := onCallHTTP(t, ctx, app, onCallWire(id, rules...), true)
	require.Empty(t, errs)
	stored, err := f.schedules.OnCallNotificationRules(ctx, nil, id)
	require.NoError(t, err)
	require.Len(t, stored, 50)
	require.Equal(t, id.String()+":49", stored[49].ID.String())
	before := onCallInventory(t, ctx, db, id)
	rules = append(rules, onCallRuleWire("", "https://limit-50.test.invalid/", "", nil))
	_, errs = onCallHTTP(t, ctx, app, onCallWire(id, rules...), true)
	require.NotEmpty(t, errs)
	require.Equal(t, before, onCallInventory(t, ctx, db, id))
}
