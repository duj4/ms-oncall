package guard

import (
	"context"
	"database/sql"
	"slices"

	"github.com/google/uuid"
	"github.com/lib/pq"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/internal/scheduledataref"
)

const userProfile = "user-only-v1"

// StabilizeUser preserves the existing three-table Store/trigger protocol before
// taking any User row. All reverse-order row acquisitions are NOWAIT. The User
// UPDATE lock closes immediate inbound FKs and the cooperating JSON writers.
// Neither the witness nor these locks grant an independent child capability.
func StabilizeUser(ctx context.Context, tx *sql.Tx, raw []Selector) (context.Context, []ds.Resource, error) {
	if ctx == nil || tx == nil || len(raw) == 0 || len(raw) > 50 {
		return ctx, nil, unavailable()
	}
	s := &stability{tx: tx, nonce: uuid.New(), rawHash: digest(raw), kind: ds.ResourceUser, profile: userProfile}
	s.epoch, s.generation = nextEpoch(tx)
	var ids []string
	for _, sel := range raw {
		id, err := uuid.Parse(sel.ID)
		if err != nil || sel.Kind != ds.ResourceUser {
			return ctx, nil, unavailable()
		}
		ids = append(ids, id.String())
	}
	ids = mergeIDs(ids)
	if _, err := tx.ExecContext(ctx, `LOCK TABLE public.rotation_participants,public.rotation_state,public.user_overrides IN EXCLUSIVE MODE NOWAIT`); err != nil {
		return ctx, nil, unavailable()
	}
	r := stableReader{ctx: ctx, tx: tx}
	roots, err := r.lockChildren(`SELECT id::text FROM public.users WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return ctx, nil, err
	}
	ids = column(roots, 0) // never reintroduce raw Missing selectors
	if len(ids) > 0 {
		if err = r.lockUserClosure(ids); err != nil {
			return ctx, nil, err
		}
	}
	for _, id := range ids {
		s.targets = append(s.targets, ds.Resource{Kind: ds.ResourceUser, ID: id})
	}
	s.effectiveHash = digest(s.targets)
	if _, err = tx.ExecContext(ctx, witnessDDL); err != nil {
		return ctx, nil, unavailable()
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO pg_temp.d09_nr_deletion_witness(nonce,phase,profile,raw_hash,effective_hash,xid) VALUES($1,'locked',$2,$3,$4,pg_current_xact_id()::text)`, s.nonce, s.profile, s.rawHash[:], s.effectiveHash[:]); err != nil {
		return ctx, nil, unavailable()
	}
	return context.WithValue(ctx, stabilityKey{}, s), slices.Clone(s.targets), nil
}

func (r *stableReader) lockUserClosure(ids []string) error {
	cms, err := r.lockChildren(`SELECT id::text,user_id::text FROM public.user_contact_methods WHERE user_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	cmIDs := column(cms, 0)
	owners := map[string]string{}
	for _, row := range cms {
		owners[row[0]] = row[1]
	}
	nrs, err := r.lockChildren(`SELECT id::text,user_id::text,contact_method_id::text FROM public.user_notification_rules WHERE user_id=ANY($1::uuid[]) OR contact_method_id=ANY($2::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids), pq.Array(cmIDs))
	if err != nil {
		return err
	}
	for _, row := range nrs {
		if owners[row[2]] != row[1] {
			return unavailable()
		}
	}
	subjects, err := r.lockChildren(`SELECT id::text,user_id::text,COALESCE(cm_id::text,'') FROM public.auth_subjects WHERE user_id=ANY($1::uuid[]) OR cm_id=ANY($2::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids), pq.Array(cmIDs))
	if err != nil {
		return err
	}
	for _, row := range subjects {
		if !slices.Contains(ids, row[1]) || row[2] != "" && owners[row[2]] != row[1] {
			return unavailable()
		}
	}
	// Only safe Session identities cross this boundary. Authentication locators
	// and credentials are neither selected nor used as audit identities.
	sessions, err := r.lockChildren(`SELECT audit_resource_id::text,user_id::text,(audit_resource_id<>id AND NOT EXISTS(SELECT FROM public.auth_user_sessions other WHERE other.id=auth_user_sessions.audit_resource_id))::text FROM public.auth_user_sessions WHERE user_id=ANY($1::uuid[]) ORDER BY audit_resource_id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	for _, row := range sessions {
		if row[0] == uuid.Nil.String() || row[2] != "true" {
			return unavailable()
		}
	}
	if _, err = r.lockChildren(`SELECT user_id::text FROM public.auth_basic_users WHERE user_id=ANY($1::uuid[]) ORDER BY user_id LIMIT 10001`, pq.Array(ids)); err != nil {
		return err
	}
	// These physical effects have no complete SD8 B2 projection. Root/CM FK
	// barriers make absence stable; positive shapes remain unsupported, including
	// closed cycles and credential-bearing resources. Never silently cascade.
	var unsupported bool
	if err = r.tx.QueryRowContext(r.ctx, `SELECT
 EXISTS(SELECT FROM public.outgoing_messages WHERE user_id=ANY($1::uuid[]) OR contact_method_id=ANY($2::uuid[])) OR
 EXISTS(SELECT FROM public.user_verification_codes WHERE contact_method_id=ANY($2::uuid[])) OR
 EXISTS(SELECT FROM public.alert_status_subscriptions WHERE contact_method_id=ANY($2::uuid[])) OR
 EXISTS(SELECT FROM public.user_calendar_subscriptions WHERE user_id=ANY($1::uuid[])) OR
 EXISTS(SELECT FROM public.user_slack_data WHERE id=ANY($1::uuid[])) OR
 EXISTS(SELECT FROM public.gql_api_keys WHERE created_by=ANY($1::uuid[]) OR updated_by=ANY($1::uuid[]) OR deleted_by=ANY($1::uuid[])) OR
 EXISTS(SELECT FROM public.users WHERE alert_status_log_contact_method_id=ANY($2::uuid[]) AND NOT(id=ANY($1::uuid[])))`, pq.Array(ids), pq.Array(cmIDs)).Scan(&unsupported); err != nil || unsupported {
		return unavailable()
	}
	cycles, err := r.lockChildren(`SELECT id::text,alert_id::text FROM public.notification_policy_cycles WHERE user_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	alerts, err := r.read(`SELECT id::text FROM public.alerts WHERE id=ANY($1::bigint[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(column(cycles, 1)))
	if err != nil || !slices.Equal(column(alerts, 0), column(cycles, 1)) {
		return unavailable()
	}
	if err = r.charge(alerts); err != nil {
		return err
	}
	// Stabilize every supported surviving referent, history and ownership row,
	// including DELETE and non-key retargets that an FK alone cannot freeze.
	sets := []struct{ query string }{
		{`SELECT id::text,escalation_policy_step_id::text FROM public.escalation_policy_actions WHERE user_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`},
		{`SELECT id::text,schedule_id::text FROM public.schedule_rules WHERE tgt_user_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`},
		{`SELECT id::text,rotation_id::text FROM public.rotation_participants WHERE user_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`},
		{`SELECT id::text,tgt_schedule_id::text,COALESCE(add_user_id::text,''),COALESCE(remove_user_id::text,'') FROM public.user_overrides WHERE add_user_id=ANY($1::uuid[]) OR remove_user_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`},
		{`SELECT id::text,schedule_id::text FROM public.schedule_on_call_users WHERE user_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`},
		{`SELECT id::text,ep_step_id::text FROM public.ep_step_on_call_users WHERE user_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`},
		{`SELECT id::text,user_id::text,COALESCE(tgt_user_id::text,''),COALESCE(tgt_service_id::text,''),COALESCE(tgt_schedule_id::text,''),COALESCE(tgt_rotation_id::text,''),COALESCE(tgt_escalation_policy_id::text,'') FROM public.user_favorites WHERE user_id=ANY($1::uuid[]) OR tgt_user_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`},
	}
	var schedules, rotations, steps, policies, services []string
	users := slices.Clone(ids)
	for i, set := range sets {
		rows, err := r.lockChildren(set.query, pq.Array(ids))
		if err != nil {
			return err
		}
		switch i {
		case 0, 5:
			steps = mergeIDs(steps, column(rows, 1))
		case 1, 4:
			schedules = mergeIDs(schedules, column(rows, 1))
		case 2:
			rotations = mergeIDs(rotations, column(rows, 1))
		case 3:
			schedules = mergeIDs(schedules, column(rows, 1))
			users = mergeIDs(users, column(rows, 2), column(rows, 3))
		case 6:
			users = mergeIDs(users, column(rows, 1), column(rows, 2))
			services = mergeIDs(services, column(rows, 3))
			schedules = mergeIDs(schedules, column(rows, 4))
			rotations = mergeIDs(rotations, column(rows, 5))
			policies = mergeIDs(policies, column(rows, 6))
		}
	}
	jsonSchedules, err := r.lockUserJSON(ids)
	if err != nil {
		return err
	}
	schedules = mergeIDs(schedules, jsonSchedules)
	lockedSteps, err := r.read(`SELECT id::text,escalation_policy_id::text FROM public.escalation_policy_steps WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(steps))
	if err != nil || !slices.Equal(column(lockedSteps, 0), steps) {
		return unavailable()
	}
	if err = r.charge(lockedSteps); err != nil {
		return err
	}
	policies = mergeIDs(policies, column(lockedSteps, 1))
	var orgs []string
	for _, set := range []struct {
		table string
		ids   []string
	}{{"schedules", schedules}, {"rotations", rotations}, {"escalation_policies", policies}, {"services", services}} {
		rows, err := r.read(`SELECT id::text,organization_id::text FROM public.`+set.table+` WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(set.ids))
		if err != nil || !slices.Equal(column(rows, 0), set.ids) {
			return unavailable()
		}
		if err = r.charge(rows); err != nil {
			return err
		}
		orgs = mergeIDs(orgs, column(rows, 1))
	}
	return r.lockServiceScope(users, orgs)
}

// Scan complete JSON, including ended references, under the User FK/writer
// barrier. Only matching envelopes are locked; unrelated Schedules remain free.
// Compare identity, parent and xmin after NOWAIT to reject changed membership.
func (r *stableReader) lockUserJSON(ids []string) ([]string, error) {
	rows, err := r.read(`SELECT id::text,schedule_id::text,CASE WHEN sum(octet_length(data::text)) OVER(ORDER BY id)<=1048576 THEN data::text ELSE '' END,xmin::text FROM public.schedule_data ORDER BY id LIMIT 10001`)
	if err != nil {
		return nil, err
	}
	if err = r.charge(rows); err != nil {
		return nil, err
	}
	var matched [][]string
	bytes := 0
	for _, row := range rows {
		bytes += len(row[2])
		if bytes > scheduledataref.MaxBytes {
			return nil, unavailable()
		}
		refs, err := scheduledataref.Users([]byte(row[2]), uuid.MustParse(row[1]))
		if err != nil {
			return nil, unavailable()
		}
		if slices.ContainsFunc(refs, func(id uuid.UUID) bool { return slices.Contains(ids, id.String()) }) {
			matched = append(matched, []string{row[0], row[1], row[3]})
		}
	}
	locked, err := r.read(`SELECT id::text,schedule_id::text,xmin::text FROM public.schedule_data WHERE id=ANY($1::bigint[]) ORDER BY id LIMIT 10001 FOR UPDATE NOWAIT`, pq.Array(column(matched, 0)))
	if err != nil || !sameRows(matched, locked) {
		return nil, unavailable()
	}
	return column(locked, 1), nil
}

func StableUser(ctx context.Context, tx *sql.Tx, root ds.Resource) bool {
	if ctx == nil || root.Kind != ds.ResourceUser {
		return false
	}
	s, _ := ctx.Value(stabilityKey{}).(*stability)
	return s != nil && s.kind == root.Kind && s.profile == userProfile && slices.Contains(s.targets, root) && s.witness(ctx, tx, "locked")
}

func ConsumeUser(ctx context.Context, tx *sql.Tx, ids []string) ([]string, error) {
	return consume(ctx, tx, ds.ResourceUser, ids)
}

func UserTargets(ctx context.Context, tx *sql.Tx, ids []string) ([]string, error) {
	return certifiedTargets(ctx, tx, ds.ResourceUser, ids, false)
}
