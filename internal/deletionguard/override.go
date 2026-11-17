package guard

import (
	"context"
	"database/sql"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	ds "github.com/target/goalert/deletionsafety"
)

// StabilizeUserOverride enters the existing Store/trigger table protocol first.
// Cleanup's direct DELETE also conflicts with EXCLUSIVE. Schedule deletion can
// hold its parent before requesting this table: all subsequent locks are NOWAIT.
// This retains cross-Schedule Override contention, without fencing other roots.
func StabilizeUserOverride(ctx context.Context, tx *sql.Tx, raw []Selector) (context.Context, []ds.Resource, error) {
	if ctx == nil || tx == nil || len(raw) == 0 || len(raw) > 50 {
		return ctx, nil, unavailable()
	}
	s := &stability{tx: tx, nonce: uuid.New(), rawHash: digest(raw), kind: ds.ResourceUserOverride, profile: overrideProfile}
	s.epoch, s.generation = nextEpoch(tx)
	var ids []string
	for _, sel := range raw {
		id, err := uuid.Parse(sel.ID)
		if err != nil || sel.Kind != ds.ResourceUserOverride {
			return ctx, nil, unavailable()
		}
		ids = append(ids, id.String())
	}
	ids = mergeIDs(ids)
	if _, err := tx.ExecContext(ctx, `LOCK TABLE public.user_overrides IN EXCLUSIVE MODE NOWAIT`); err != nil {
		return ctx, nil, unavailable()
	}
	r := stableReader{ctx: ctx, tx: tx}
	const query = `SELECT id::text,tgt_schedule_id::text,COALESCE(add_user_id::text,''),COALESCE(remove_user_id::text,''),start_time::text,end_time::text FROM public.user_overrides WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`
	roots, err := r.lockChildren(query, pq.Array(ids))
	if err != nil {
		return ctx, nil, err
	}
	parents := column(roots, 1)
	schedules, err := r.read(`SELECT id::text,organization_id::text FROM public.schedules WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(parents))
	if err != nil || !slices.Equal(column(schedules, 0), parents) {
		return ctx, nil, unavailable()
	}
	if err = r.charge(schedules); err != nil {
		return ctx, nil, err
	}
	if err = r.lockServiceScope(mergeIDs(column(roots, 2), column(roots, 3)), column(schedules, 1)); err != nil {
		return ctx, nil, err
	}
	// A new RC statement after every real scope lock. No pre-lock JOIN or
	// client-supplied Schedule/User is accepted as stable membership.
	fresh, err := r.read(query, pq.Array(ids))
	if err != nil || !sameRows(roots, fresh) {
		return ctx, nil, unavailable()
	}
	for _, row := range roots {
		s.targets = append(s.targets, ds.Resource{Kind: ds.ResourceUserOverride, ID: row[0]})
	}
	// Locks freeze facts, not time. All roots use this single database statement
	// observation, even if collection, certification or DML crosses a boundary.
	if err = tx.QueryRowContext(ctx, `SELECT statement_timestamp()`).Scan(&s.observedAt); err != nil {
		return ctx, nil, unavailable()
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

// UserOverrideObservation is valid only under this transaction's locked witness.
func UserOverrideObservation(ctx context.Context, tx *sql.Tx, root ds.Resource) (time.Time, bool) {
	if ctx == nil || root.Kind != ds.ResourceUserOverride {
		return time.Time{}, false
	}
	s, _ := ctx.Value(stabilityKey{}).(*stability)
	if s == nil || s.kind != root.Kind || s.profile != overrideProfile || s.observedAt.IsZero() || !slices.Contains(s.targets, root) || !s.witness(ctx, tx, "locked") {
		return time.Time{}, false
	}
	return s.observedAt, true
}

func ConsumeUserOverride(ctx context.Context, tx *sql.Tx, ids []string) ([]string, error) {
	return consume(ctx, tx, ds.ResourceUserOverride, ids)
}
