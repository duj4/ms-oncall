package migrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	audit "github.com/target/goalert/schedule/jsonupdateaudit"
)

func TestScheduleJSON308CanonicalAppend(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(h.entries), 308)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-schedule-json-update-audit-d09-contract-impl1\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte{}, h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	require.Equal(t, "ae4dc5d87e36355e07d38dc518c2975909e9aef6e39705dea7878bb43671f51d", fmt.Sprintf("%x", sha256.Sum256(prefix)))
	require.Equal(t, int64(308), h.entries[307].Position)
	require.Equal(t, h.entries[306].ID, h.entries[307].PredecessorID)
	parsed, err := parseMigrations(h)
	require.NoError(t, err)
	require.False(t, parsed[307].Up.disableTx)
}

func scheduleJSONHTTP(t *testing.T, ctx context.Context, app *graphqlapp.App, wire map[string]any, clear, mutation bool) (*graphql2.UpdateDeletionPreview, []json.RawMessage) {
	t.Helper()
	field, typ := "setTemporarySchedule", "SetTemporaryScheduleInput"
	if clear {
		field, typ = "clearTemporarySchedules", "ClearTemporarySchedulesInput"
	}
	op, selection := "mutation", ""
	if !mutation {
		op = "query"
		field = "preview" + string(bytes.ToUpper([]byte(field[:1]))) + field[1:]
		selection = `{impactVersion complete canProceed requiresConfirmation removed{type id} impacts{relation change policy} scheduleJSONUpdate{contractVersion operation mode before{kind userID start end} after{kind userID start end} effects{change source coverage{kind userID start end}}}}`
	}
	payload, err := json.Marshal(map[string]any{"query": op + "($input:" + typ + "!){result:" + field + "(input:$input)" + selection + "}", "variables": map[string]any{"input": wire}})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(payload)).WithContext((config.Config{}).Context(ctx))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	var result struct {
		Data   map[string]json.RawMessage
		Errors []json.RawMessage
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result), w.Body.String())
	var preview *graphql2.UpdateDeletionPreview
	if !mutation && len(result.Errors) == 0 {
		require.NoError(t, json.Unmarshal(result.Data["result"], &preview))
	}
	return preview, result.Errors
}
func scheduleJSONSetWire(id uuid.UUID, temp schedule.TemporarySchedule) map[string]any {
	shifts := make([]map[string]any, 0, len(temp.Shifts))
	for _, s := range temp.Shifts {
		shifts = append(shifts, map[string]any{"userID": s.UserID, "start": s.Start, "end": s.End})
	}
	return map[string]any{"scheduleID": id.String(), "start": temp.Start, "end": temp.End, "shifts": shifts}
}
func scheduleJSONConfirm(p *graphql2.UpdateDeletionPreview) map[string]any {
	return map[string]any{"expectedImpactVersion": p.ImpactVersion, "acknowledgeImpacts": true}
}
func scheduleJSONInventory(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	var s string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_build_array((SELECT to_jsonb(d) FROM schedule_data d WHERE schedule_id=$1),(SELECT jsonb_agg(to_jsonb(a) ORDER BY event_id) FROM schedule_json_update_audit_events a WHERE schedule_id=$1))::text`, id).Scan(&s))
	return s
}
func TestPostgresScheduleJSONUpdateGraphQL(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "ScheduleJSONContractTest")
	f := newUserPhaseAFixture(t, ctx, db)
	app := updateNativeApp(t, ctx, db)
	app.UserStore = f.users
	app.ScheduleStore = f.schedules
	for _, mode := range []string{"set", "set_clear", "clear", "empty_shifts", "active_clear"} {
		t.Run(mode, func(t *testing.T) {
			id := f.newSchedule(t, ctx)
			temp := userPhaseATemp(f.user)
			if mode == "active_clear" {
				temp.Start = time.Now().Add(-time.Hour).Truncate(time.Minute)
				temp.End = time.Now().Add(3 * time.Hour).Truncate(time.Minute)
				temp.Shifts = []schedule.FixedShift{{Start: temp.Start, End: temp.End, UserID: f.user.String()}}
			}
			wire := scheduleJSONSetWire(id, temp)
			_, errs := scheduleJSONHTTP(t, ctx, app, wire, false, true)
			require.Empty(t, errs)
			before := scheduleJSONInventory(t, ctx, db, id)
			var change map[string]any
			clear := mode == "clear" || mode == "active_clear"
			if clear {
				change = map[string]any{"scheduleID": id.String(), "start": temp.Start, "end": temp.End}
			} else {
				next := temp
				next.Shifts = []schedule.FixedShift{}
				if mode != "empty_shifts" {
					next.Start = next.Start.Add(15 * time.Minute)
					next.End = next.End.Add(-15 * time.Minute)
				}
				change = scheduleJSONSetWire(id, next)
				if mode == "set_clear" {
					change["clearStart"] = temp.Start
					change["clearEnd"] = temp.End
				}
			}
			p, errs := scheduleJSONHTTP(t, ctx, app, change, clear, false)
			require.Empty(t, errs)
			require.True(t, p.Complete && p.CanProceed && p.RequiresConfirmation)
			require.Empty(t, p.Removed)
			require.NotEmpty(t, p.ScheduleJSONUpdate.Effects)
			require.Equal(t, before, scheduleJSONInventory(t, ctx, db, id), "Preview must not write JSON or success audit")
			for _, c := range []any{nil, map[string]any{"acknowledgeImpacts": true}, map[string]any{"acknowledgeImpacts": false, "expectedImpactVersion": p.ImpactVersion}, map[string]any{"acknowledgeImpacts": true, "expectedImpactVersion": "forged.invalid"}} {
				if c == nil {
					delete(change, "confirmation")
				} else {
					change["confirmation"] = c
				}
				_, errs = scheduleJSONHTTP(t, ctx, app, change, clear, true)
				require.NotEmpty(t, errs)
				require.Equal(t, before, scheduleJSONInventory(t, ctx, db, id))
			}
			change["confirmation"] = scheduleJSONConfirm(p)
			_, errs = scheduleJSONHTTP(t, ctx, app, change, clear, true)
			require.Empty(t, errs)
			require.NotEqual(t, before, scheduleJSONInventory(t, ctx, db, id))
			var b, a []byte
			require.NoError(t, db.QueryRowContext(ctx, `SELECT before_coverage,after_coverage FROM schedule_json_update_audit_events WHERE schedule_id=$1 ORDER BY occurred_at DESC LIMIT 1`, id).Scan(&b, &a))
			var after []audit.Coverage
			require.NoError(t, json.Unmarshal(a, &after))
			tx := userPhaseATx(t, ctx, db)
			_, actual, err := f.schedules.ReadTemporaryUpdate(ctx, tx, id, false)
			require.NoError(t, err)
			require.NoError(t, tx.Rollback())
			projected, err := schedule.TemporaryCoverage(actual)
			require.NoError(t, err)
			require.Equal(t, projected, after)
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, id))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
			require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_json_update_audit_events WHERE schedule_id=$1`, id))
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1`, id))
		})
	}
}

func TestPostgresScheduleJSONUpdateStoreBypassAndRollback(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "ScheduleJSONContractTest")
	f := newUserPhaseAFixture(t, ctx, db)
	app := updateNativeApp(t, ctx, db)
	app.ScheduleStore = f.schedules
	app.UserStore = f.users
	id := f.newSchedule(t, ctx)
	temp := userPhaseATemp(f.user)
	require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, id, temp, &f.org))
	before := scheduleJSONInventory(t, ctx, db, id)
	for _, mode := range []string{"set", "set_scoped", "clear_set", "clear_set_scoped", "clear", "clear_scoped"} {
		t.Run(mode, func(t *testing.T) {
			tx := userPhaseATx(t, ctx, db)
			var err error
			switch mode {
			case "set", "set_scoped":
				empty := temp
				empty.Shifts = nil
				if mode == "set" {
					err = f.schedules.SetTemporarySchedule(ctx, tx, id, empty)
				} else {
					err = f.schedules.SetTemporaryScheduleScoped(ctx, tx, id, empty, &f.org)
				}
			case "clear_set", "clear_set_scoped":
				small := temp
				small.Start = small.Start.Add(15 * time.Minute)
				small.End = small.End.Add(-15 * time.Minute)
				small.Shifts = nil
				if mode == "clear_set" {
					err = f.schedules.SetClearTemporarySchedule(ctx, tx, id, small, temp.Start, temp.End)
				} else {
					err = f.schedules.SetClearTemporaryScheduleScoped(ctx, tx, id, small, temp.Start, temp.End, &f.org)
				}
			case "clear":
				err = f.schedules.ClearTemporarySchedules(ctx, tx, id, temp.Start, temp.End)
			default:
				err = f.schedules.ClearTemporarySchedulesScoped(ctx, tx, id, temp.Start, temp.End, &f.org)
			}
			enforceCode(t, err, ds.DeletionConfirmationRequired)
			require.NoError(t, tx.Commit(), "caller can continue after rejected writer savepoint")
			require.Equal(t, before, scheduleJSONInventory(t, ctx, db, id))
		})
	}
	clear := map[string]any{"scheduleID": id.String(), "start": temp.Start, "end": temp.End}
	p, errs := scheduleJSONHTTP(t, ctx, app, clear, true, false)
	require.Empty(t, errs)
	clear["confirmation"] = scheduleJSONConfirm(p)
	for _, point := range []string{"json_write", "audit_append", "audit_constraint", "deferred_commit", "actual_write_mismatch"} {
		t.Run(point, func(t *testing.T) {
			table, timing, body := "schedule_json_update_audit_events", "BEFORE", "RAISE EXCEPTION 'synthetic injected fault';"
			if point == "json_write" {
				table = "schedule_data"
			}
			if point == "actual_write_mismatch" {
				table = "schedule_data"
				body = `NEW.data=jsonb_set(NEW.data,'{V1,TemporarySchedules}',OLD.data#>'{V1,TemporarySchedules}'); RETURN NEW;`
			}
			if point == "audit_constraint" {
				body = "NEW.effect_count=-1; RETURN NEW;"
			}
			if point == "deferred_commit" {
				timing = "AFTER"
			}
			enforcementExec(t, ctx, db, `CREATE FUNCTION schedule_json_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+body+` END $$`)
			if point == "deferred_commit" {
				enforcementExec(t, ctx, db, `CREATE CONSTRAINT TRIGGER schedule_json_fault AFTER INSERT ON `+table+` DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION schedule_json_fault()`)
			} else {
				enforcementExec(t, ctx, db, `CREATE TRIGGER schedule_json_fault `+timing+` INSERT OR UPDATE ON `+table+` FOR EACH ROW EXECUTE FUNCTION schedule_json_fault()`)
			}
			_, errs := scheduleJSONHTTP(t, ctx, app, clear, true, true)
			require.NotEmpty(t, errs)
			enforcementExec(t, ctx, db, `DROP TRIGGER schedule_json_fault ON `+table)
			enforcementExec(t, ctx, db, `DROP FUNCTION schedule_json_fault()`)
			require.Equal(t, before, scheduleJSONInventory(t, ctx, db, id))
		})
	}
}
