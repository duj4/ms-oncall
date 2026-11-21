package guard

import (
	"context"
	"database/sql"
	"slices"

	"github.com/google/uuid"
	"github.com/lib/pq"
	ds "github.com/target/goalert/deletionsafety"
)

// StabilizeRotation preserves the existing Participant -> State EXCLUSIVE
// protocol before taking any Rotation root lock. NOWAIT also covers writers
// that start with State or a root. This intentionally retains the two tables'
// cross-Rotation contention; it is not the former global Collector fence.
func StabilizeRotation(ctx context.Context, tx *sql.Tx, raw []Selector) (context.Context, []ds.Resource, error) {
	if ctx == nil || tx == nil || len(raw) == 0 || len(raw) > 50 {
		return ctx, nil, unavailable()
	}
	s := &stability{tx: tx, nonce: uuid.New(), rawHash: digest(raw), kind: ds.ResourceRotation, profile: rotationProfile}
	s.epoch, s.generation = nextEpoch(tx)
	var ids []string
	for _, sel := range raw {
		id, err := uuid.Parse(sel.ID)
		if err != nil || sel.Kind != ds.ResourceRotation {
			return ctx, nil, unavailable()
		}
		ids = append(ids, id.String())
	}
	ids = mergeIDs(ids)
	if _, err := tx.ExecContext(ctx, `LOCK TABLE public.rotation_participants,public.rotation_state IN EXCLUSIVE MODE NOWAIT`); err != nil {
		return ctx, nil, unavailable()
	}
	// EP Step triggers request EXCLUSIVE before their parent. Take the normal
	// locking-SELECT relation mode now, never wait for it while holding a root.
	if _, err := tx.ExecContext(ctx, `LOCK TABLE public.escalation_policy_steps IN ROW SHARE MODE NOWAIT`); err != nil {
		return ctx, nil, unavailable()
	}
	r := stableReader{ctx: ctx, tx: tx}
	roots, err := r.lockChildren(`SELECT id::text,organization_id::text,participant_count::text FROM public.rotations WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return ctx, nil, err
	}
	for _, row := range roots {
		s.targets = append(s.targets, ds.Resource{Kind: ds.ResourceRotation, ID: row[0]})
	}
	if err := r.lockRotationClosure(roots); err != nil {
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

func (r *stableReader) lockRotationClosure(roots [][]string) error {
	ids := column(roots, 0)
	rules, err := r.lockChildren(`SELECT id::text,schedule_id::text,tgt_rotation_id::text FROM public.schedule_rules WHERE tgt_rotation_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	actions, err := r.lockChildren(`SELECT id::text,escalation_policy_step_id::text,rotation_id::text FROM public.escalation_policy_actions WHERE rotation_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	schedules, err := r.read(`SELECT id::text,organization_id::text FROM public.schedules WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(column(rules, 1)))
	if err != nil || !slices.Equal(column(schedules, 0), column(rules, 1)) {
		return unavailable()
	}
	steps, err := r.read(`SELECT id::text,escalation_policy_id::text FROM public.escalation_policy_steps WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(column(actions, 1)))
	if err != nil || !slices.Equal(column(steps, 0), column(actions, 1)) {
		return unavailable()
	}
	policies, err := r.read(`SELECT id::text,organization_id::text FROM public.escalation_policies WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(column(steps, 1)))
	if err != nil || !slices.Equal(column(policies, 0), column(steps, 1)) {
		return unavailable()
	}
	participants, err := r.lockChildren(`SELECT id::text,rotation_id::text,user_id::text,position::text FROM public.rotation_participants WHERE rotation_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	// Both FK directions matter: even a cross-linked runtime row must remain
	// visible to the Collector, which rejects an inconsistent closure.
	_, err = r.lockChildren(`SELECT id::text,rotation_id::text,rotation_participant_id::text,position::text,shift_start::text,version::text FROM public.rotation_state WHERE rotation_id=ANY($1::uuid[]) OR rotation_participant_id=ANY($2::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids), pq.Array(column(participants, 0)))
	if err != nil {
		return err
	}
	favorites, err := r.lockChildren(`SELECT id::text,tgt_rotation_id::text,user_id::text FROM public.user_favorites WHERE tgt_rotation_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	for _, rows := range [][][]string{schedules, steps, policies} {
		if err := r.charge(rows); err != nil {
			return err
		}
	}
	// No State cleanup or policy inference here. Collect/Authorize/Plan/Check
	// must all succeed before Bind can certify this transaction's witness.
	return r.lockServiceScope(mergeIDs(column(participants, 2), column(favorites, 2)), mergeIDs(column(roots, 1), column(schedules, 1), column(policies, 1)))
}
