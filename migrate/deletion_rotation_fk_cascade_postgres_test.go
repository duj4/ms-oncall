package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/permission"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
)

type rotationCascadePlan struct {
	Query string `json:"Query Text"`
	Plan  struct {
		Operation string `json:"Operation"`
		Plans     []struct {
			Rows  int `json:"Actual Rows"`
			Loops int `json:"Actual Loops"`
		} `json:"Plans"`
	} `json:"Plan"`
}

// The session-local auto_explain observer changes no schema, trigger, FK, or
// product code. It exposes nested SQL executed by the original enabled triggers;
// checking only the final empty tables cannot establish the State's mechanism.
// This evidence test asserts the observed blocker, NOT Phase A acceptance:
// Participants use FK CASCADE, but State is removed by the Participant trigger.
func TestPostgresDeletionEnforcementRotationFKCascadeStateBoundary(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationFKCascadeProof")
	var version string
	require.NoError(t, db.QueryRowContext(ctx, `SHOW server_version`).Scan(&version))
	require.Equal(t, "17.11", version)
	for _, fk := range []struct {
		table, name, parent, action string
		deferrable, deferred        bool
	}{
		{"rotation_state", "rotation_state_rotation_id_fkey", "rotations", "c", false, false},
		{"rotation_participants", "rotation_participants_rotation_id_fkey", "rotations", "c", false, false},
		{"rotation_state", "rotation_state_rotation_participant_id_fkey", "rotation_participants", "a", true, false},
		{"rotation_participants", "rotation_participants_user_id_fkey", "users", "c", false, false},
	} {
		var parent, action, definition string
		var deferrable, deferred bool
		require.NoError(t, db.QueryRowContext(ctx, `SELECT confrelid::regclass::text,confdeltype::text,condeferrable,condeferred,pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid=('public.'||$1)::regclass AND conname=$2 AND contype='f'`, fk.table, fk.name).Scan(&parent, &action, &deferrable, &deferred, &definition))
		require.Equal(t, fk.parent, parent)
		require.Equal(t, fk.action, action)
		require.Equal(t, fk.deferrable, deferrable)
		require.Equal(t, fk.deferred, deferred)
		t.Log(fk.table, fk.name, definition)
	}
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM pg_trigger WHERE tgrelid IN ('public.rotations'::regclass,'public.rotation_state'::regclass,'public.rotation_participants'::regclass) AND tgenabled<>'O'`))
	// A State DELETE cannot be suppressed by a State BEFORE/INSTEAD OF trigger.
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM pg_trigger WHERE tgrelid='public.rotation_state'::regclass AND (tgtype::int & 8)<>0 AND (tgtype::int & (2|64))<>0`))
	rows, err := db.QueryContext(ctx, `SELECT t.tgname,c.conname,p.proname FROM pg_trigger t JOIN pg_constraint c ON c.oid=t.tgconstraint JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid='public.rotations'::regclass AND c.conname IN ('rotation_state_rotation_id_fkey','rotation_participants_rotation_id_fkey') AND p.proname='RI_FKey_cascade_del' ORDER BY t.tgname`)
	require.NoError(t, err)
	for rows.Next() {
		var trigger, constraint, function string
		require.NoError(t, rows.Scan(&trigger, &constraint, &function))
		t.Log("Root DELETE catalog trigger order:", trigger, constraint, function)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())

	app := enforcementApp(t, ctx, db)
	for _, count := range []int{1, 2, 5} {
		for active := range count {
			t.Run(fmt.Sprintf("participants-%d/active-%d", count, active), func(t *testing.T) {
				f := newRotationProfileFixture(t, ctx, db)
				users := make([]string, count)
				for i := range users {
					users[i] = f.user.String()
				}
				require.NoError(t, app.RotationStore.AddRotationUsersTx(ctx, nil, f.root.String(), users))
				require.NoError(t, app.RotationStore.SetActiveIndexTx(ctx, nil, f.root.String(), active))
				before := rotationStateContractInventory(t, ctx, db)
				retainedBefore := rotationCascadeRetainedInventory(t, ctx, db, f.root)
				var notices []pgconn.Notice
				cfg, err := pgx.ParseConfig(uri)
				require.NoError(t, err)
				cfg.OnNotice = func(_ *pgconn.PgConn, notice *pgconn.Notice) {
					notices = append(notices, *notice)
				}
				observed := stdlib.OpenDB(*cfg)
				t.Cleanup(func() { require.NoError(t, observed.Close()) })
				observed.SetMaxOpenConns(1)
				tx := nrBegin(t, ctx, observed)
				_, _, err = guard.StabilizeRotation(ctx, tx, rotationProfileSelectors(f.root))
				require.NoError(t, err)
				for _, sql := range []string{
					`LOAD 'auto_explain'`,
					`SET LOCAL auto_explain.log_min_duration=0`,
					`SET LOCAL auto_explain.log_nested_statements=on`,
					`SET LOCAL auto_explain.log_analyze=on`,
					`SET LOCAL auto_explain.log_timing=off`,
					`SET LOCAL auto_explain.log_format='json'`,
					`SET LOCAL auto_explain.log_level='notice'`,
				} {
					_, err = tx.ExecContext(ctx, sql)
					require.NoError(t, err)
				}
				notices = nil
				var receipt sraudit.Receipt
				// Sole explicit business DELETE. No State/Participant cleanup,
				// constraint deferral, test substitute, or hidden child DML.
				require.NoError(t, tx.QueryRowContext(ctx, `DELETE FROM rotations WHERE id=$1 RETURNING id,organization_id`, f.root).Scan(&receipt.ID, &receipt.OrganizationID))
				require.Equal(t, sraudit.Receipt{ID: f.root, OrganizationID: f.org}, receipt)
				var fkParticipants, fkState, triggerState, fkParticipantCalls, fkStateCalls int
				for _, notice := range notices {
					i := strings.Index(notice.Message, "{\n")
					if i < 0 {
						continue
					}
					var plan rotationCascadePlan
					require.NoError(t, json.Unmarshal([]byte(notice.Message[i:]), &plan))
					if plan.Plan.Operation == "Update" && strings.HasPrefix(plan.Query, "UPDATE rotation_state") {
						require.Len(t, plan.Plan.Plans, 1)
						require.Zero(t, plan.Plan.Plans[0].Rows, "no transient State update during deletion")
					}
					if plan.Plan.Operation != "Delete" {
						continue
					}
					require.Len(t, plan.Plan.Plans, 1)
					input := plan.Plan.Plans[0].Rows * plan.Plan.Plans[0].Loops
					switch {
					case strings.HasPrefix(plan.Query, `DELETE FROM ONLY "public"."rotation_participants"`):
						fkParticipants += input
						fkParticipantCalls++
					case strings.HasPrefix(plan.Query, `DELETE FROM ONLY "public"."rotation_state"`):
						fkState += input
						fkStateCalls++
					case strings.HasPrefix(plan.Query, `DELETE FROM rotation_state`):
						require.Contains(t, notice.Where, "fn_advance_or_end_rot_on_part_del()")
						triggerState += input
					default:
						require.NotContains(t, plan.Query, "rotation_participants", "no hidden explicit Participant DELETE")
						require.NotContains(t, plan.Query, "rotation_state", "no unknown State DELETE")
						continue
					}
					t.Logf("Native nested DELETE scan rows=%d SQL=%s", input, strings.Join(strings.Fields(plan.Query), " "))
				}
				require.Equal(t, 1, fkParticipantCalls)
				require.Equal(t, 1, fkStateCalls)
				require.Equal(t, count, fkParticipants)
				for _, table := range []string{"rotations", "rotation_state", "rotation_participants"} {
					column := "rotation_id"
					if table == "rotations" {
						column = "id"
					}
					var n int
					require.NoError(t, tx.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` WHERE `+column+`=$1`, f.root).Scan(&n))
					require.Zero(t, n)
				}
				var retained int
				require.NoError(t, tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE id=$1`, f.user).Scan(&retained))
				require.Equal(t, 1, retained)
				var other uuid.UUID
				require.NoError(t, tx.QueryRowContext(ctx, `SELECT rotation_participant_id FROM rotation_state WHERE rotation_id=$1`, f.rotation).Scan(&other))
				require.Equal(t, retainedBefore, rotationCascadeRetainedInventory(t, ctx, tx, f.root), "all retained business inventory unchanged before rollback")
				require.NoError(t, tx.Rollback())
				require.Equal(t, before, rotationStateContractInventory(t, ctx, db))
				t.Log("Direct root DELETE: no FK error; all owned rows gone; User/other State retained; full rollback exact")
				t.Logf("Physical State mechanism: trigger DELETE rows=%d; FK CASCADE rows=%d", triggerState, fkState)
				require.Equal(t, 1, triggerState, "the enabled original Participant trigger actually removes State")
				require.Zero(t, fkState, "State's FK runs after the trigger already removed it: Phase A remains HOLD")
			})
		}
	}
}

func rotationCascadeRetainedInventory(t *testing.T, ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, root uuid.UUID) string {
	t.Helper()
	var inventory string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_build_object(
	 'rotations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM rotations r WHERE id<>$1),
	 'participants',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM rotation_participants p WHERE rotation_id<>$1),
	 'state',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM rotation_state s WHERE rotation_id<>$1),
	 'users',(SELECT jsonb_agg(id ORDER BY id) FROM users),
	 'assignments',(SELECT jsonb_agg(jsonb_build_object('user',user_id,'org',effective_organization_id,'role',organization_role) ORDER BY user_id) FROM user_organization_assignments),
	 'schedules',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM schedules s),
	 'rules',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM schedule_rules r),
	 'policies',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM escalation_policies p),
	 'actions',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM escalation_policy_actions a))::text`, root).Scan(&inventory))
	return inventory
}
