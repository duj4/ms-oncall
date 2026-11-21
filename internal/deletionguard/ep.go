package guard

import (
	"context"
	"database/sql"
	"slices"

	"github.com/google/uuid"
	"github.com/lib/pq"
	ds "github.com/target/goalert/deletionsafety"
)

// StabilizeEP obtains the existing Step triggers' EXCLUSIVE relation lock before
// any EP row. INSERT's count trigger updates the EP before its numbering trigger
// requests EXCLUSIVE; DELETE also updates the EP before requesting EXCLUSIVE.
// Taking only an EP row first, or taking ROW SHARE then upgrading during CASCADE,
// can deadlock against those writers. Acquire the final mode NOWAIT up front;
// every subsequent row lock is NOWAIT as well. No trigger/writer is weakened.
// This necessarily serializes Step DML across EPs, just as the frozen triggers do.
func StabilizeEP(ctx context.Context, tx *sql.Tx, raw []Selector) (context.Context, []ds.Resource, error) {
	if ctx == nil || tx == nil || len(raw) == 0 || len(raw) > 50 {
		return ctx, nil, unavailable()
	}
	s := &stability{tx: tx, nonce: uuid.New(), rawHash: digest(raw), kind: ds.ResourceEscalationPolicy, profile: epProfile}
	s.epoch, s.generation = nextEpoch(tx)
	var ids []string
	for _, sel := range raw {
		id, err := uuid.Parse(sel.ID)
		if err != nil || sel.Kind != ds.ResourceEscalationPolicy {
			return ctx, nil, unavailable()
		}
		ids = append(ids, id.String())
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if _, err := tx.ExecContext(ctx, `LOCK TABLE public.escalation_policy_steps IN EXCLUSIVE MODE NOWAIT`); err != nil {
		return ctx, nil, unavailable()
	}
	// The existing Message Manager takes EXCLUSIVE before parent rows. Request
	// our ordinary locking-SELECT relation mode before those rows, without waiting.
	if _, err := tx.ExecContext(ctx, `LOCK TABLE public.outgoing_messages IN ROW SHARE MODE NOWAIT`); err != nil {
		return ctx, nil, unavailable()
	}
	r := stableReader{ctx: ctx, tx: tx}
	roots, err := r.lockChildren(`SELECT id::text,organization_id::text FROM public.escalation_policies WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return ctx, nil, err
	}
	for _, row := range roots {
		s.targets = append(s.targets, ds.Resource{Kind: ds.ResourceEscalationPolicy, ID: row[0]})
	}
	if err := r.lockEPClosure(roots); err != nil {
		return ctx, nil, err
	}
	s.effectiveHash = digest(s.targets)
	if _, err := tx.ExecContext(ctx, witnessDDL); err != nil {
		return ctx, nil, unavailable()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO pg_temp.d09_nr_deletion_witness(nonce,phase,profile,raw_hash,effective_hash,xid) VALUES($1,'locked',$2,$3,$4,pg_current_xact_id()::text)`, s.nonce, s.profile, s.rawHash[:], s.effectiveHash[:]); err != nil {
		return ctx, nil, unavailable()
	}
	return context.WithValue(ctx, stabilityKey{}, s), slices.Clone(s.targets), nil
}

func (r *stableReader) lockEPClosure(roots [][]string) error {
	ids := column(roots, 0)
	services, err := r.lockChildren(`SELECT id::text,organization_id::text,escalation_policy_id::text FROM public.services WHERE escalation_policy_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	// UPDATE on the actual EP blocks new Service/Step/Message/Favorite FKs;
	// existing Service UPDATE freezes retargets and new Alert membership.
	steps, err := r.lockChildren(`SELECT id::text,escalation_policy_id::text,step_number::text FROM public.escalation_policy_steps WHERE escalation_policy_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	actions, err := r.lockChildren(`SELECT id::text,escalation_policy_step_id::text,COALESCE(user_id::text,''),COALESCE(schedule_id::text,''),COALESCE(rotation_id::text,''),COALESCE(channel_id::text,'') FROM public.escalation_policy_actions WHERE escalation_policy_step_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(column(steps, 0)))
	if err != nil {
		return err
	}
	favorites, err := r.lockChildren(`SELECT id::text,tgt_escalation_policy_id::text,user_id::text FROM public.user_favorites WHERE tgt_escalation_policy_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	alerts, err := r.lockChildren(`SELECT id::text,service_id::text,status::text FROM public.alerts WHERE service_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(column(services, 0)))
	if err != nil {
		return err
	}
	cycles, err := r.lockChildren(`SELECT id::text,alert_id::text,user_id::text FROM public.notification_policy_cycles WHERE alert_id=ANY($1::bigint[]) ORDER BY id LIMIT 10001`, pq.Array(column(alerts, 0)))
	if err != nil {
		return err
	}
	states, err := r.lockChildren(`SELECT id::text,service_id::text,alert_id::text,escalation_policy_id::text,COALESCE(escalation_policy_step_id::text,'') FROM public.escalation_policy_state WHERE escalation_policy_id=ANY($1::uuid[]) OR escalation_policy_step_id=ANY($2::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids), pq.Array(column(steps, 0)))
	if err != nil {
		return err
	}
	for _, state := range states {
		// Valid runtime necessarily has a surviving Service -> EP reference:
		// let the complete Collector/Planner report that non-bypassable BLOCK.
		// Foreign-step or otherwise incomplete runtime never reaches certification.
		if !slices.ContainsFunc(services, func(s []string) bool { return s[0] == state[1] && s[2] == state[3] }) ||
			!slices.ContainsFunc(alerts, func(a []string) bool { return a[0] == state[2] && a[1] == state[1] }) ||
			state[4] != "" && !slices.ContainsFunc(steps, func(st []string) bool { return st[0] == state[4] && st[1] == state[3] }) {
			return unavailable()
		}
	}
	// On-call history and messages have no B2 effect representation in the
	// frozen EP audit envelope. Preserve them, including closed history, and
	// refuse the entire attempt rather than silently cascade unaudited rows.
	for _, set := range []struct {
		query string
		args  []any
	}{
		{`SELECT id::text FROM public.ep_step_on_call_users WHERE ep_step_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, []any{pq.Array(column(steps, 0))}},
		{`SELECT id::text FROM public.outgoing_messages WHERE escalation_policy_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, []any{pq.Array(ids)}},
	} {
		rows, err := r.lockChildren(set.query, set.args...)
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			return unavailable()
		}
	}
	// No schedule/history rows are owned by EP. Action targets are retained;
	// SHARE freezes their state/organization and prevents deletion CASCADE from
	// silently removing an Action while its parent EP is being certified.
	if err := r.lockEPTargets(roots, steps, actions); err != nil {
		return err
	}
	targetOrgs, err := r.read(`SELECT organization_id::text FROM public.schedules WHERE id=ANY($1::uuid[]) UNION SELECT organization_id::text FROM public.rotations WHERE id=ANY($2::uuid[]) ORDER BY 1 LIMIT 10001`, pq.Array(mergeIDs(column(actions, 3))), pq.Array(mergeIDs(column(actions, 4))))
	if err != nil {
		return err
	}
	if err := r.charge(targetOrgs); err != nil {
		return err
	}
	return r.lockServiceScope(mergeIDs(column(actions, 2), column(favorites, 2), column(cycles, 2)), mergeIDs(column(roots, 1), column(services, 1), column(targetOrgs, 0)))
}

func (r *stableReader) lockEPTargets(roots, steps, actions [][]string) error {
	for _, a := range actions {
		count := 0
		for _, id := range a[2:] {
			if id != "" {
				count++
			}
		}
		// Channel scope has no organization FK; keep that existing shape closed.
		if count != 1 || a[5] != "" {
			return unavailable()
		}
	}
	for _, target := range []struct {
		index int
		query string
	}{
		{2, `SELECT id::text FROM public.users WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`},
		{3, `SELECT id::text FROM public.schedules WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`},
		{4, `SELECT id::text FROM public.rotations WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`},
	} {
		ids := mergeIDs(column(actions, target.index))
		rows, err := r.read(target.query, pq.Array(ids))
		if err != nil || !slices.Equal(column(rows, 0), ids) {
			return unavailable()
		}
		if err := r.charge(rows); err != nil {
			return err
		}
	}
	// Scope-producing assignments are locked by lockServiceScope, then the
	// complete Collector resolves every typed target and checks actual scope.
	// Parent membership itself was re-read under EP/Step/Action UPDATE locks.
	for _, a := range actions {
		if !slices.ContainsFunc(steps, func(st []string) bool {
			return st[0] == a[1] && slices.Contains(column(roots, 0), st[1])
		}) {
			return unavailable()
		}
	}
	return nil
}
