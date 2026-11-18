package migrate

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/config"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/internal/oncalljsonguard"
	"github.com/target/goalert/notification/webhook"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	audit "github.com/target/goalert/schedule/oncallupdateaudit"
)

func TestPostgresOnCall309AuthorityAndVersions(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "OnCall309Test")
	f, actor, other := newUserPhaseAFixture(t, ctx, db), newUserPhaseAFixture(t, ctx, db), newUserPhaseAFixture(t, ctx, db)
	for _, id := range []uuid.UUID{actor.user, other.user} {
		enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2,organization_role='ORG_ADMIN' WHERE user_id=$1`, id, f.org)
	}
	app := onCallNativeApp(t, ctx, db, f)
	id, _ := onCallSeed(t, ctx, db, app, f)
	wire := onCallWire(id)
	human := previewAdmit(t, base, db, actor.user)
	p, errs := onCallHTTP(t, human, app, wire, false)
	require.Empty(t, errs)
	wire["confirmation"] = scheduleJSONConfirm(p)
	before := onCallInventory(t, ctx, db, id)
	for _, denied := range []context.Context{previewAdmit(t, base, db, f.user), previewAdmit(t, base, db, newUserPhaseAFixture(t, ctx, db).user)} {
		_, errs = onCallHTTP(t, denied, app, wire, false)
		require.NotEmpty(t, errs)
		_, errs = onCallHTTP(t, denied, app, wire, true)
		require.NotEmpty(t, errs)
	}
	_, errs = onCallHTTP(t, previewAdmit(t, base, db, other.user), app, wire, true)
	require.NotEmpty(t, errs, "consent is actor-bound")
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, actor.user)
	_, errs = onCallHTTP(t, human, app, wire, true)
	require.NotEmpty(t, errs)
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, actor.user)
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, actor.user, other.org)
	_, errs = onCallHTTP(t, human, app, wire, true)
	require.NotEmpty(t, errs, "persisted actor Organization changes invalidate consent")
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, actor.user, f.org)
	enforcementExec(t, ctx, db, `UPDATE schedules SET organization_id=$2 WHERE id=$1`, id, other.org)
	_, errs = onCallHTTP(t, human, app, wire, false)
	require.NotEmpty(t, errs)
	_, errs = onCallHTTP(t, human, app, wire, true)
	require.NotEmpty(t, errs, "Schedule Organization changes invalidate consent")
	enforcementExec(t, ctx, db, `UPDATE schedules SET organization_id=$2 WHERE id=$1`, id, f.org)
	// A different surviving destination intent cannot reuse clear consent.
	altered := onCallWire(id, onCallRuleWire("", "https://changed-intent.test.invalid/", "", nil))
	altered["confirmation"] = scheduleJSONConfirm(p)
	_, errs = onCallHTTP(t, human, app, altered, true)
	require.NotEmpty(t, errs)
	raw, _, ok := strings.Cut(p.ImpactVersion, ".")
	require.True(t, ok)
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	require.NoError(t, err)
	var expired struct {
		Digest string `json:"digest"`
		At     int64  `json:"at"`
	}
	require.NoError(t, json.Unmarshal(payload, &expired))
	expired.At = time.Now().Add(-6 * time.Minute).UnixNano()
	payload, err = json.Marshal(expired)
	require.NoError(t, err)
	sig, err := (previewNativeSigner{}).Sign(append([]byte("goalert.update-induced-deletion.v1\x00oncall-json.v1\x00"), payload...))
	require.NoError(t, err)
	wire["confirmation"] = map[string]any{"acknowledgeImpacts": true, "expectedImpactVersion": base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)}
	_, errs = onCallHTTP(t, human, app, wire, true)
	require.NotEmpty(t, errs)
	copyApp := *app
	copyApp.PreviewSigner = scheduleJSONNativeFailSigner{}
	_, errs = onCallHTTP(t, human, &copyApp, wire, false)
	require.NotEmpty(t, errs)
	require.Equal(t, before, onCallInventory(t, ctx, db, id))
	wire["confirmation"] = scheduleJSONConfirm(p)
	_, errs = onCallHTTP(t, human, app, wire, true)
	require.Empty(t, errs)
	// Local identity can be reused after real removal. Only a new addition is
	// audited; historical events do not pretend to own that ID permanently.
	add := onCallWire(id, onCallRuleWire(id.String()+":0", "https://recreated.test.invalid/", "", nil))
	p, errs = onCallHTTP(t, human, app, add, false)
	require.Empty(t, errs)
	require.False(t, p.RequiresConfirmation)
	require.Len(t, p.OnCallJSONUpdate.Effects, 1)
	require.Equal(t, "rule_added", p.OnCallJSONUpdate.Effects[0].Change)
	_, errs = onCallHTTP(t, human, app, add, true)
	require.Empty(t, errs)
}

func onCallTyped(t *testing.T, ctx context.Context, db *sql.DB, f userPhaseAFixture, id uuid.UUID, clear bool) graphql2.SetScheduleOnCallNotificationRulesInput {
	t.Helper()
	rules, err := f.schedules.OnCallNotificationRules(ctx, nil, id)
	require.NoError(t, err)
	if clear {
		rules = rules[:0]
	} else {
		rules = rules[:1]
	}
	input := graphql2.SetScheduleOnCallNotificationRulesInput{ScheduleID: id.String(), Rules: []graphql2.OnCallNotificationRuleInput{}}
	for _, r := range rules {
		var destJSON []byte
		require.NoError(t, db.QueryRowContext(ctx, `SELECT dest FROM notification_channels WHERE id=$1`, r.ChannelID).Scan(&destJSON))
		v := graphql2.OnCallNotificationRuleInput{OnCallNotificationRule: r}
		require.NoError(t, json.Unmarshal(destJSON, &v.Dest))
		input.Rules = append(input.Rules, v)
	}
	return input
}

func onCallWaitBlocked(t *testing.T, ctx context.Context, db *sql.DB, done <-chan error) {
	t.Helper()
	for {
		var blocked bool
		require.NoError(t, db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND cardinality(pg_blocking_pids(pid))>0 AND query LIKE '%schedule_data%')`).Scan(&blocked))
		if blocked {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("writer did not reach PostgreSQL lock wait: %v", err)
		default:
		}
		require.NoError(t, ctx.Err())
	}
}

func TestPostgresOnCall309Concurrency(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	db.SetMaxOpenConns(16)
	ctx := permission.SystemContext(base, "OnCall309Test")
	var cfg config.Config
	cfg.Webhook.Enable = true
	ctx = cfg.Context(ctx)
	f := newUserPhaseAFixture(t, ctx, db)
	app := onCallNativeApp(t, ctx, db, f)
	for _, mode := range []string{"notification", "temporary", "schedule_delete", "user_delete", "channel", "next_notification"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			id, _ := onCallSeed(t, ctx, db, app, f)
			temp := userPhaseATemp(f.user)
			require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, id, temp, &f.org))
			first := onCallTyped(t, ctx, db, f, id, false)
			p, err := app.Query().PreviewSetScheduleOnCallNotificationRules(ctx, first)
			require.NoError(t, err)
			first.Confirmation = updateNativeConfirmation(p)
			second := onCallTyped(t, ctx, db, f, id, true)
			p, err = app.Query().PreviewSetScheduleOnCallNotificationRules(ctx, second)
			require.NoError(t, err)
			second.Confirmation = updateNativeConfirmation(p)
			var rootConfirmation *graphql2.DeletionSafetyConfirmationInput
			if mode == "schedule_delete" {
				rootConfirmation = enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeSchedule, ID: id.String()})
			}
			traced, barrier := jsonWriterTraced(t, uri, "-- name: SchedUpdateData")
			store, err := schedule.NewStore(ctx, traced, f.users)
			require.NoError(t, err)
			copyApp := *app
			copyApp.DB = traced
			copyApp.ScheduleStore = store
			done := make(chan error, 1)
			go func() { _, err := copyApp.Mutation().SetScheduleOnCallNotificationRules(ctx, first); done <- err }()
			jsonWriterWait(t, ctx, barrier, done)
			var concurrent chan error
			switch mode {
			case "notification":
				concurrent = make(chan error, 1)
				go func() { _, err := app.Mutation().SetScheduleOnCallNotificationRules(ctx, second); concurrent <- err }()
				onCallWaitBlocked(t, ctx, db, concurrent)
			case "temporary":
				concurrent = make(chan error, 1)
				newTemp := temp
				newTemp.Start = newTemp.End.Add(time.Hour)
				newTemp.End = newTemp.Start.Add(time.Hour)
				newTemp.Shifts = []schedule.FixedShift{{UserID: f.user.String(), Start: newTemp.Start, End: newTemp.End}}
				go func() { concurrent <- f.schedules.SetTemporaryScheduleScoped(ctx, nil, id, newTemp, &f.org) }()
				onCallWaitBlocked(t, ctx, db, concurrent)
			case "schedule_delete":
				_, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeSchedule, ID: id.String()}}, rootConfirmation)
				require.Error(t, err)
			case "user_delete":
				tx := userPhaseATx(t, ctx, db)
				jsonWriterCode(t, jsonWriterUserLock(ctx, tx, f.user), "55P03")
				require.NoError(t, tx.Rollback())
				_, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: f.user.String()}}, nil)
				require.Error(t, err)
			case "channel":
				tx := userPhaseATx(t, ctx, db)
				_, err := tx.ExecContext(ctx, `UPDATE notification_channels SET name=name WHERE id=$1`, first.Rules[0].ChannelID)
				jsonWriterCode(t, err, "55P03")
				require.NoError(t, tx.Rollback())
			case "next_notification":
				concurrent = make(chan error, 1)
				go func() {
					tx, err := db.BeginTx(ctx, nil)
					if err != nil {
						concurrent <- err
						return
					}
					defer func() { _ = tx.Rollback() }()
					_, err = tx.ExecContext(ctx, `UPDATE schedule_data SET data=jsonb_set(data,'{V1,OnCallNotificationRules,0,NextNotification}',to_jsonb('2030-01-01T00:00:00Z'::text)) WHERE schedule_id=$1`, id)
					if err == nil {
						err = tx.Commit()
					}
					concurrent <- err
				}()
				onCallWaitBlocked(t, ctx, db, concurrent)
			}
			close(barrier.resume)
			require.NoError(t, <-done)
			if concurrent != nil {
				err := <-concurrent
				if mode == "notification" {
					require.Error(t, err, "fresh locked state invalidates second writer's consent")
				} else {
					require.NoError(t, err)
				}
			}
			current, err := f.schedules.OnCallNotificationRules(ctx, nil, id)
			require.NoError(t, err)
			require.Len(t, current, 1)
			if mode == "next_notification" {
				require.NotNil(t, current[0].NextNotification)
			}
			require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_oncall_update_audit_events WHERE schedule_id=$1`, id))
			temps, err := f.schedules.TemporarySchedules(ctx, nil, id)
			require.NoError(t, err)
			require.NotEmpty(t, temps)
		})
	}
}

func TestPostgresOnCall309LockedFreshRead(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	db.SetMaxOpenConns(10)
	ctx := permission.SystemContext(base, "OnCall309Test")
	var cfg config.Config
	cfg.Webhook.Enable = true
	ctx = cfg.Context(ctx)
	f := newUserPhaseAFixture(t, ctx, db)
	app := onCallNativeApp(t, ctx, db, f)
	for _, mode := range []string{"temporary", "next_notification", "channel", "rules", "scope"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			id, _ := onCallSeed(t, ctx, db, app, f)
			input := onCallTyped(t, ctx, db, f, id, false)
			p, err := app.Query().PreviewSetScheduleOnCallNotificationRules(ctx, input)
			require.NoError(t, err)
			input.Confirmation = updateNativeConfirmation(p)
			tx := userPhaseATx(t, ctx, db)
			var envelope int64
			require.NoError(t, tx.QueryRowContext(ctx, `SELECT id FROM schedule_data WHERE schedule_id=$1 FOR UPDATE`, id).Scan(&envelope))
			var systemNext string
			switch mode {
			case "temporary":
				temp := userPhaseATemp(f.user)
				require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, tx, id, temp, &f.org))
			case "next_notification":
				systemNext = "2030-01-01T00:00:00Z"
				_, err = tx.ExecContext(ctx, `UPDATE schedule_data SET data=jsonb_set(data,'{V1,OnCallNotificationRules,0,NextNotification}',to_jsonb($2::text)) WHERE schedule_id=$1`, id, systemNext)
				require.NoError(t, err)
			case "channel":
				_, err = tx.ExecContext(ctx, `UPDATE notification_channels SET dest=jsonb_set(dest,'{Args,webhook_url}','"https://changed-channel.test.invalid/"') WHERE id=$1`, input.Rules[0].ChannelID)
				require.NoError(t, err)
			case "rules":
				_, err = tx.ExecContext(ctx, `UPDATE schedule_data SET data=jsonb_set(data,'{V1,OnCallNotificationRules,1,Time}','"10:00"') WHERE schedule_id=$1`, id)
				require.NoError(t, err)
			case "scope":
				_, err = tx.ExecContext(ctx, `UPDATE schedules SET time_zone='Asia/Shanghai' WHERE id=$1`, id)
				require.NoError(t, err)
			}
			done := make(chan error, 1)
			go func() { _, err := app.Mutation().SetScheduleOnCallNotificationRules(ctx, input); done <- err }()
			onCallWaitBlocked(t, ctx, db, done)
			require.NoError(t, tx.Commit())
			err = <-done
			if mode == "temporary" || mode == "next_notification" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				return
			}
			if mode == "temporary" {
				temp, err := f.schedules.TemporarySchedules(ctx, nil, id)
				require.NoError(t, err)
				require.NotEmpty(t, temp)
			}
			if mode == "next_notification" {
				rules, err := f.schedules.OnCallNotificationRules(ctx, nil, id)
				require.NoError(t, err)
				require.NotNil(t, rules[0].NextNotification)
				require.Equal(t, systemNext, rules[0].NextNotification.Format(time.RFC3339))
			}
		})
	}
}

func TestPostgresOnCall309CapabilityIsolation(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "OnCall309Test")
	f := newUserPhaseAFixture(t, ctx, db)
	app := onCallNativeApp(t, ctx, db, f)
	id, _ := onCallSeed(t, ctx, db, app, f)
	tx := userPhaseATx(t, ctx, db)
	envelope, rules, err := f.schedules.ReadOnCallUpdate(ctx, tx, id, false)
	require.NoError(t, err)
	b, err := schedule.OnCallSnapshot(id, rules)
	require.NoError(t, err)
	a := []audit.Rule{}
	effects, err := audit.Diff(id, b, a)
	require.NoError(t, err)
	e := audit.Event{Version: 1, EventID: uuid.New(), RequestID: uuid.New(), AttemptID: uuid.New(), ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", ScheduleID: id, OrganizationID: f.org, EnvelopeID: envelope, Operation: audit.Operation, OccurredAt: time.Now(), Before: b, After: a, Effects: effects}
	guarded, err := oncalljsonguard.Bind(ctx, tx, e)
	require.NoError(t, err)
	before := onCallInventory(t, ctx, db, id)
	other := userPhaseATx(t, ctx, db)
	require.Error(t, f.schedules.SetOnCallNotificationRulesScoped(guarded, other, id, nil, &f.org))
	require.NoError(t, other.Commit())
	require.Equal(t, before, onCallInventory(t, ctx, db, id))
	wrong := e
	wrong.OrganizationID = uuid.New()
	wrongContext, err := oncalljsonguard.Bind(ctx, tx, wrong)
	require.NoError(t, err)
	require.Error(t, f.schedules.SetOnCallNotificationRulesScoped(wrongContext, tx, id, nil, &f.org))
	require.NoError(t, f.schedules.SetOnCallNotificationRulesScoped(guarded, tx, id, nil, &f.org))
	require.Error(t, f.schedules.SetOnCallNotificationRulesScoped(guarded, tx, id, rules, &f.org), "consumed capability cannot apply another write")
	require.NoError(t, tx.Commit())
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_oncall_update_audit_events WHERE schedule_id=$1`, id))
}

func TestPostgresOnCall309PendingChannelRace(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "OnCall309Test")
	var cfg config.Config
	cfg.Webhook.Enable = true
	ctx = cfg.Context(ctx)
	f := newUserPhaseAFixture(t, ctx, db)
	app := onCallNativeApp(t, ctx, db, f)
	id, _ := onCallSeed(t, ctx, db, app, f)
	dest := webhook.NewWebhookDest("https://raced-mapping.test.invalid/" + uuid.NewString())
	wire := onCallWire(id, onCallRuleWire("", dest.Arg(webhook.FieldWebhookURL), "", nil))
	p, errs := onCallHTTP(t, ctx, app, wire, false)
	require.Empty(t, errs)
	wire["confirmation"] = scheduleJSONConfirm(p)
	other := userPhaseATx(t, ctx, db)
	actual, err := app.NCStore.MapDestToID(ctx, other, dest)
	require.NoError(t, err)
	require.NoError(t, other.Commit())
	require.NotEqual(t, p.OnCallJSONUpdate.After[0].ChannelID, actual.String())
	before := onCallInventory(t, ctx, db, id)
	_, errs = onCallHTTP(t, ctx, app, wire, true)
	require.NotEmpty(t, errs)
	require.Equal(t, before, onCallInventory(t, ctx, db, id))
	// A new preview binds the real committed mapping and can execute normally.
	p, errs = onCallHTTP(t, ctx, app, wire, false)
	require.Empty(t, errs)
	wire["confirmation"] = scheduleJSONConfirm(p)
	_, errs = onCallHTTP(t, ctx, app, wire, true)
	require.Empty(t, errs)
}
