package guard

import (
	"context"
	"database/sql"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/permission"
)

// All statements have bounded result sets. Membership is compared by identity
// AND parent/owner, never counts alone. Rows are not authorized by discovery.
const stableRowBudget = 10000

type stableReader struct {
	ctx   context.Context
	tx    *sql.Tx
	count int
}

func (r *stableReader) read(query string, args ...any) ([][]string, error) {
	rows, err := r.tx.QueryContext(r.ctx, query, args...)
	if err != nil {
		return nil, unavailable()
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, unavailable()
	}
	var result [][]string
	for rows.Next() {
		row := make([]string, len(cols))
		dest := make([]any, len(cols))
		for i := range row {
			dest[i] = &row[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, unavailable()
		}
		result = append(result, row)
		if len(result) > stableRowBudget {
			return nil, &ds.DeletionSafetyError{Code: ds.DeletionPreviewLimitExceeded}
		}
	}
	if rows.Err() != nil {
		return nil, unavailable()
	}
	return result, nil
}
func (r *stableReader) charge(rows [][]string) error {
	r.count += len(rows)
	if r.count > stableRowBudget {
		return &ds.DeletionSafetyError{Code: ds.DeletionPreviewLimitExceeded}
	}
	return nil
}
func sameRows(a, b [][]string) bool { return slices.EqualFunc(a, b, slices.Equal[[]string]) }
func column(rows [][]string, index int) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row[index])
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// StabilizeNR is the ONLY creator of the private stability checkpoint. It
// acquires actual business rows, then re-reads after the owner FK barrier. All
// new locks use NOWAIT, preserving CM -> NR -> User order without a reverse
// waiting chain against existing Stores/triggers. No global table lock is used.
// The caller already owns D09's audit advisory lock and a writable RC tx.
func StabilizeNR(ctx context.Context, tx *sql.Tx, raw []Selector) (context.Context, []ds.Resource, error) {
	if ctx == nil || tx == nil || len(raw) == 0 || len(raw) > 50 {
		return ctx, nil, unavailable()
	}
	s := &stability{tx: tx, nonce: uuid.New(), rawHash: digest(raw)}
	s.epoch, s.generation = nextEpoch(tx) // revoke even when the new attempt fails
	ids := make([]string, 0, len(raw))
	for _, sel := range raw {
		id, err := uuid.Parse(sel.ID)
		if err != nil || sel.Kind != ds.ResourceNotificationRule {
			return ctx, nil, unavailable()
		}
		ids = append(ids, id.String())
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	r := stableReader{ctx: ctx, tx: tx}
	selected, err := r.read(`SELECT id::text,user_id::text,contact_method_id::text FROM public.user_notification_rules WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return ctx, nil, err
	}
	owners := column(selected, 1)
	parents := column(selected, 2)
	cmQuery := `SELECT id::text,user_id::text FROM public.user_contact_methods WHERE user_id=ANY($1::uuid[]) OR id=ANY($2::uuid[]) ORDER BY id LIMIT 10001`
	nrQuery := `SELECT id::text,user_id::text,contact_method_id::text FROM public.user_notification_rules WHERE user_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`
	cms, err := r.read(cmQuery, pq.Array(owners), pq.Array(parents))
	if err != nil {
		return ctx, nil, err
	}
	nrs, err := r.read(nrQuery, pq.Array(owners))
	if err != nil {
		return ctx, nil, err
	}
	for _, set := range [][][]string{cms, nrs} {
		if err := r.charge(set); err != nil {
			return ctx, nil, err
		}
	}
	lockedCM, err := r.read(`SELECT id::text,user_id::text FROM public.user_contact_methods WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE NOWAIT`, pq.Array(column(cms, 0)))
	if err != nil || !sameRows(cms, lockedCM) {
		return ctx, nil, unavailable()
	}
	lockedNR, err := r.read(`SELECT id::text,user_id::text,contact_method_id::text FROM public.user_notification_rules WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE NOWAIT`, pq.Array(column(nrs, 0)))
	if err != nil || !sameRows(nrs, lockedNR) {
		return ctx, nil, unavailable()
	}
	users, err := r.read(`SELECT id::text FROM public.users WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE NOWAIT`, pq.Array(owners))
	if err != nil || !slices.Equal(column(users, 0), owners) {
		return ctx, nil, unavailable()
	}
	// This NEW statement snapshot follows all owner UPDATE locks. A sibling that
	// entered during discovery cannot be silently omitted, even if now committed.
	freshCM, err := r.read(cmQuery, pq.Array(owners), pq.Array(parents))
	if err != nil {
		return ctx, nil, err
	}
	freshNR, err := r.read(nrQuery, pq.Array(owners))
	if err != nil {
		return ctx, nil, err
	}
	if !sameRows(cms, freshCM) || !sameRows(nrs, freshNR) {
		return ctx, nil, unavailable()
	}
	cmOwners := map[string]string{}
	for _, row := range cms {
		cmOwners[row[0]] = row[1]
	}
	for _, row := range nrs {
		if cmOwners[row[2]] != row[1] {
			return ctx, nil, unavailable()
		}
	}
	for _, row := range selected {
		if !slices.ContainsFunc(nrs, func(n []string) bool { return slices.Equal(n, row) }) {
			return ctx, nil, unavailable()
		}
		s.targets = append(s.targets, ds.Resource{Kind: ds.ResourceNotificationRule, ID: row[0]})
	}
	// Owner UPDATE blocks new/retargeted Cycle FKs; SHARE stabilizes existing
	// cycles and alerts, including non-key status updates and deletion.
	cycleQuery := `SELECT id::text,user_id::text,alert_id::text FROM public.notification_policy_cycles WHERE user_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`
	cycles, err := r.read(cycleQuery+` FOR SHARE NOWAIT`, pq.Array(owners))
	if err != nil {
		return ctx, nil, err
	}
	if err = r.charge(cycles); err != nil {
		return ctx, nil, err
	}
	alerts, err := r.read(`SELECT id::text FROM public.alerts WHERE id=ANY($1::bigint[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(column(cycles, 2)))
	if err != nil || !slices.Equal(column(alerts, 0), column(cycles, 2)) {
		return ctx, nil, unavailable()
	}
	if err = r.charge(alerts); err != nil {
		return ctx, nil, err
	}
	freshCycles, err := r.read(cycleQuery, pq.Array(owners))
	if err != nil || !sameRows(cycles, freshCycles) {
		return ctx, nil, unavailable()
	}
	scopeUsers := slices.Clone(owners)
	if !permission.System(ctx) {
		actor, err := uuid.Parse(permission.UserID(ctx))
		if err != nil || actor == uuid.Nil {
			return ctx, nil, unavailable()
		}
		scopeUsers = append(scopeUsers, actor.String())
	}
	slices.Sort(scopeUsers)
	scopeUsers = slices.Compact(scopeUsers)
	actors, err := r.read(`SELECT id::text FROM public.users WHERE id=ANY($1::uuid[]) ORDER BY id FOR SHARE NOWAIT`, pq.Array(scopeUsers))
	if err != nil || !slices.Equal(column(actors, 0), scopeUsers) {
		return ctx, nil, unavailable()
	}
	assignments, err := r.read(`SELECT user_id::text,effective_organization_id::text,COALESCE(effective_normal_organization_id::text,'') FROM public.user_organization_assignments WHERE user_id=ANY($1::uuid[]) ORDER BY user_id FOR SHARE NOWAIT`, pq.Array(scopeUsers))
	if err != nil || !slices.Equal(column(assignments, 0), scopeUsers) {
		return ctx, nil, unavailable()
	}
	orgIDs := column(assignments, 1)
	orgs, err := r.read(`SELECT id::text FROM public.organizations WHERE id=ANY($1::uuid[]) ORDER BY id FOR SHARE NOWAIT`, pq.Array(orgIDs))
	if err != nil || !slices.Equal(column(orgs, 0), orgIDs) {
		return ctx, nil, unavailable()
	}
	normalIDs := slices.DeleteFunc(column(assignments, 2), func(id string) bool { return strings.TrimSpace(id) == "" })
	normals, err := r.read(`SELECT organization_id::text FROM public.normal_organizations WHERE organization_id=ANY($1::uuid[]) ORDER BY organization_id FOR SHARE NOWAIT`, pq.Array(normalIDs))
	if err != nil || !slices.Equal(column(normals, 0), normalIDs) {
		return ctx, nil, unavailable()
	}
	for _, set := range [][][]string{actors, assignments, orgs, normals} {
		if err = r.charge(set); err != nil {
			return ctx, nil, err
		}
	}
	// Assignments are locked before deriving organization identities; re-reading
	// them now observes only those stable identities, not a pre-lock JOIN snapshot.
	freshAssignments, err := r.read(`SELECT user_id::text,effective_organization_id::text,COALESCE(effective_normal_organization_id::text,'') FROM public.user_organization_assignments WHERE user_id=ANY($1::uuid[]) ORDER BY user_id`, pq.Array(scopeUsers))
	if err != nil || !sameRows(assignments, freshAssignments) {
		return ctx, nil, unavailable()
	}
	s.effectiveHash = digest(s.targets)
	if _, err = tx.ExecContext(ctx, witnessDDL); err != nil {
		return ctx, nil, unavailable()
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO pg_temp.d09_nr_deletion_witness(nonce,phase,profile,raw_hash,effective_hash,xid) VALUES($1,'locked',$2,$3,$4,pg_current_xact_id()::text)`, s.nonce, nrProfile, s.rawHash[:], s.effectiveHash[:]); err != nil {
		return ctx, nil, unavailable()
	}
	return context.WithValue(ctx, stabilityKey{}, s), slices.Clone(s.targets), nil
}
