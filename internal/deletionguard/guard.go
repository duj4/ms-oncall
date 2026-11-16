// Package guard binds a checked server deletion plan to one live transaction.
// It has no authorization or System bypass and owns no transaction finalization.
package guard

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"sync"

	"github.com/google/uuid"
	ds "github.com/target/goalert/deletionsafety"
)

type Selector struct {
	Kind ds.ResourceKind
	ID   string
}
type enforcementKey struct{}
type enforcementGuard struct {
	mu        sync.Mutex
	tx        *sql.Tx
	remaining map[Selector]bool
	absent    map[Selector]bool
	ready     bool
}

func unavailable() error { return &ds.DeletionSafetyError{Code: ds.DeletionUnavailable} }

// These are the complete Collector read set, including conditional unsupported
// probes and identity/scope lookups. EXCLUSIVE allows ordinary SELECT, but fences
// DML and row-locking readers. NOWAIT is essential: no reverse-order wait is
// introduced after the Controller's advisory/Rotation/root locks. Contention
// aborts the owning attempt; locks are retained until its rollback/commit.
// This deliberately conservative V1 fence has database-wide contention costs.
const enforcementTables = `alert_data alert_feedback alert_logs alert_metrics alert_status_subscriptions alerts auth_basic_users auth_subjects auth_user_sessions ep_step_on_call_users escalation_policies escalation_policy_actions escalation_policy_state escalation_policy_steps gql_api_keys heartbeat_monitors integration_keys labels message_status_history normal_organizations notification_channels notification_policy_cycles organizations outgoing_messages pending_signals rotation_participants rotation_state rotations schedule_data schedule_on_call_users schedule_rules schedules services twilio_sms_callbacks uik_config user_calendar_subscriptions user_contact_methods user_favorites user_notification_rules user_organization_assignments user_overrides user_slack_data user_verification_codes users`

type fenceKey struct{}

// Fence is internal and cannot issue deletion authority. Bind still requires a
// complete checked plan for precisely the admitted selection in this transaction.
func Fence(ctx context.Context, tx *sql.Tx) (context.Context, error) {
	if ctx == nil || tx == nil {
		return ctx, unavailable()
	}
	tables := strings.Fields(enforcementTables)
	for i := range tables {
		tables[i] = "public." + tables[i]
	}
	if _, err := tx.ExecContext(ctx, `LOCK TABLE `+strings.Join(tables, ",")+` IN EXCLUSIVE MODE NOWAIT`); err != nil {
		return ctx, unavailable()
	}
	return context.WithValue(ctx, fenceKey{}, tx), nil
}
func Fenced(ctx context.Context, tx *sql.Tx) bool {
	return ctx != nil && tx != nil && ctx.Value(fenceKey{}) == tx
}
func Tables() []string { return strings.Fields(enforcementTables) }

// Bind accepts ONLY a complete server-built plan in the already fenced owning
// transaction. Selectors are the original admitted operation (legacy key IDs
// are never serialized). Wire callers cannot construct a DeletionPlan.
func Bind(ctx context.Context, tx *sql.Tx, raw []Selector, plan ds.DeletionPlan, expected string, acknowledged bool) (context.Context, error) {
	if !Fenced(ctx, tx) || !holdsFence(ctx, tx) {
		return ctx, unavailable()
	}
	targets := plan.Targets()
	if len(targets) > 0 {
		if err := plan.Check(expected, acknowledged); err != nil {
			return ctx, err
		}
	}
	observed := map[ds.Resource]bool{}
	absent := map[Selector]bool{}
	for _, c := range plan.Changes() {
		if c.Cause == ds.CauseExplicit && c.Kind != ds.ChangeDeleted {
			return ctx, unavailable()
		}
	}
	for _, sel := range raw {
		id, err := uuid.Parse(sel.ID)
		if err != nil {
			return ctx, unavailable()
		}
		sel.ID = id.String()
		r, exists, err := resolve(ctx, tx, sel)
		if err != nil {
			return ctx, unavailable()
		}
		if !exists {
			absent[sel] = true
			continue
		}
		if r.Kind == ds.ResourceUser || !slices.Contains(targets, r) {
			return ctx, unavailable()
		}
		observed[r] = true
	}
	if len(observed) != len(targets) {
		return ctx, unavailable()
	}
	g := &enforcementGuard{tx: tx, remaining: map[Selector]bool{}, absent: absent, ready: true}
	for _, s := range raw {
		id, err := uuid.Parse(s.ID)
		if err != nil {
			return ctx, unavailable()
		}
		s.ID = id.String()
		g.remaining[s] = true
	}
	return context.WithValue(ctx, enforcementKey{}, g), nil
}

// RequireDelete consumes ONLY this Store call's authorized selectors. A copied
// context cannot authorize another transaction, operation, target, or replay.
// An ended transaction cannot use a carrier after its fences have been released.
// Every public root deletion Store (audited and legacy) calls this before DML.
func RequireDelete(ctx context.Context, tx *sql.Tx, kind ds.ResourceKind, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if ctx == nil || tx == nil {
		return unavailable()
	}
	g, _ := ctx.Value(enforcementKey{}).(*enforcementGuard)
	if g == nil {
		return unavailable()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.ready || g.tx != tx || !holdsFence(ctx, tx) {
		return unavailable()
	}
	unique := map[Selector]bool{}
	for _, id := range ids {
		parsed, err := uuid.Parse(id)
		if err != nil {
			return unavailable()
		}
		s := Selector{Kind: kind, ID: parsed.String()}
		if !g.remaining[s] {
			return unavailable()
		}
		if g.absent[s] {
			_, exists, err := resolve(ctx, tx, s)
			if err != nil || exists {
				return unavailable()
			}
		}
		unique[s] = true
	}
	var alive int
	if err := tx.QueryRowContext(ctx, `SELECT 1`).Scan(&alive); err != nil {
		return unavailable()
	}
	for s := range unique {
		delete(g.remaining, s)
	}
	return nil
}

// Safe identity resolution is repeated inside the same fenced transaction.
// It never returns credential identity or data in an error or public response.
func resolve(ctx context.Context, tx *sql.Tx, s Selector) (ds.Resource, bool, error) {
	r := ds.Resource{Kind: s.Kind, ID: s.ID}
	if s.Kind == ds.ResourceIntegrationKey {
		err := tx.QueryRowContext(ctx, `SELECT audit_resource_id::text FROM public.integration_keys WHERE id=$1::uuid`, s.ID).Scan(&r.ID)
		if err == sql.ErrNoRows {
			return r, false, nil
		}
		return r, err == nil, err
	}
	var table string
	switch s.Kind {
	case ds.ResourceService:
		table = "services"
	case ds.ResourceEscalationPolicy:
		table = "escalation_policies"
	case ds.ResourceSchedule:
		table = "schedules"
	case ds.ResourceRotation:
		table = "rotations"
	case ds.ResourceUser:
		table = "users"
	case ds.ResourceContactMethod:
		table = "user_contact_methods"
	case ds.ResourceNotificationRule:
		table = "user_notification_rules"
	case ds.ResourceUserOverride:
		table = "user_overrides"
	default:
		return r, false, unavailable()
	}
	var exists bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM public.`+table+` WHERE id=$1::uuid)`, s.ID).Scan(&exists)
	return r, exists, err
}

// Transaction identity alone is insufficient: ROLLBACK TO SAVEPOINT can release
// a fence while leaving *sql.Tx alive. Verify the actual granted relation locks
// each time a carrier is issued or consumed, before authorizing Store DML.
func holdsFence(ctx context.Context, tx *sql.Tx) bool {
	tables := strings.Fields(enforcementTables)
	for i := range tables {
		tables[i] = "'public." + tables[i] + "'"
	}
	var count int
	err := tx.QueryRowContext(ctx, `SELECT count(DISTINCT relation) FROM pg_locks WHERE locktype='relation' AND pid=pg_backend_pid() AND granted AND mode IN ('ExclusiveLock','AccessExclusiveLock') AND relation=ANY(ARRAY[`+strings.Join(tables, ",")+`]::regclass[])`).Scan(&count)
	return err == nil && count == len(tables)
}
