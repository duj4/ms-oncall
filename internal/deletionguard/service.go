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

// StabilizeService certifies only existing Service roots, using immediate FKs
// and the real Alert/AlertLog writers. All row locks are NOWAIT: cleanup and
// engine writers may already hold a child before requesting a parent. A failed
// attempt must be rolled back by DeleteAll's original transaction owner.
func StabilizeService(ctx context.Context, tx *sql.Tx, raw []Selector) (context.Context, []ds.Resource, error) {
	if ctx == nil || tx == nil || len(raw) == 0 || len(raw) > 50 {
		return ctx, nil, unavailable()
	}
	s := &stability{tx: tx, nonce: uuid.New(), rawHash: digest(raw), kind: ds.ResourceService, profile: serviceProfile}
	s.epoch, s.generation = nextEpoch(tx)
	var ids []string
	for _, sel := range raw {
		id, err := uuid.Parse(sel.ID)
		if err != nil || sel.Kind != ds.ResourceService {
			return ctx, nil, unavailable()
		}
		ids = append(ids, id.String())
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	// This is the ordinary relation mode of SELECT FOR UPDATE, acquired early
	// to avoid waiting behind the existing message manager's EXCLUSIVE->parent
	// order. It is compatible with ordinary independent INSERT/UPDATE/DELETE.
	if _, err := tx.ExecContext(ctx, `LOCK TABLE public.outgoing_messages IN ROW SHARE MODE NOWAIT`); err != nil {
		return ctx, nil, unavailable()
	}
	r := stableReader{ctx: ctx, tx: tx}
	roots, err := r.lockChildren(`SELECT id::text,organization_id::text,COALESCE(escalation_policy_id::text,'') FROM public.services WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return ctx, nil, err
	}
	// lockChildren's fresh comparison includes raw missing IDs. An insertion in
	// that discovery window rejects; later insertions stay outside the subset.
	for _, row := range roots {
		s.targets = append(s.targets, ds.Resource{Kind: ds.ResourceService, ID: row[0]})
	}
	if err := r.lockServiceClosure(roots); err != nil {
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

func (r *stableReader) lockServiceClosure(roots [][]string) error {
	ids, policies := column(roots, 0), mergeIDs(column(roots, 2))
	// Policies, steps and actions are retained. UPDATE on parents also freezes
	// incoming FK membership; this is resource-local, never a table fence.
	eps, err := r.lockChildren(`SELECT id::text,organization_id::text FROM public.escalation_policies WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(policies))
	if err != nil {
		return err
	}
	if !slices.Equal(column(eps, 0), policies) {
		return unavailable()
	}
	for _, root := range roots {
		if root[2] != "" && !slices.ContainsFunc(eps, func(ep []string) bool { return ep[0] == root[2] && ep[1] == root[1] }) {
			return unavailable()
		}
	}
	steps, err := r.lockChildren(`SELECT id::text,escalation_policy_id::text FROM public.escalation_policy_steps WHERE escalation_policy_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(policies))
	if err != nil {
		return err
	}
	if _, err := r.lockChildren(`SELECT id::text,escalation_policy_step_id::text FROM public.escalation_policy_actions WHERE escalation_policy_step_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(column(steps, 0))); err != nil {
		return err
	}
	keys, err := r.lockChildren(`SELECT audit_resource_id::text,service_id::text FROM public.integration_keys WHERE service_id=ANY($1::uuid[]) ORDER BY audit_resource_id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	// Do not SELECT credential UUIDs. Config presence is checked through an
	// internal SQL join after locking every actual key; immediate FK blocks upsert.
	var unsupported bool
	if err := r.tx.QueryRowContext(r.ctx, `SELECT EXISTS(SELECT FROM public.uik_config c JOIN public.integration_keys k ON k.id=c.id WHERE k.audit_resource_id=ANY($1::uuid[]))`, pq.Array(column(keys, 0))).Scan(&unsupported); err != nil || unsupported {
		return unavailable()
	}
	alerts, err := r.lockChildren(`SELECT id::text,service_id::text,status::text FROM public.alerts WHERE service_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	aids := column(alerts, 0)
	cycles, err := r.lockChildren(`SELECT id::text,alert_id::text,user_id::text FROM public.notification_policy_cycles WHERE alert_id=ANY($1::bigint[]) ORDER BY id LIMIT 10001`, pq.Array(aids))
	if err != nil {
		return err
	}
	states, err := r.lockChildren(`SELECT id::text,service_id::text,alert_id::text,escalation_policy_id::text,COALESCE(escalation_policy_step_id::text,'') FROM public.escalation_policy_state WHERE service_id=ANY($1::uuid[]) OR alert_id=ANY($2::bigint[]) ORDER BY id LIMIT 10001`, pq.Array(ids), pq.Array(aids))
	if err != nil {
		return err
	}
	for _, row := range states {
		if !slices.Contains(ids, row[1]) || !slices.Contains(aids, row[2]) || !slices.Contains(policies, row[3]) || row[4] != "" && !slices.Contains(column(steps, 0), row[4]) {
			return unavailable()
		}
	}
	for _, table := range []string{"alert_data", "alert_feedback", "alert_metrics"} {
		// Identifiers are a closed internal list; no payload or feedback is read.
		if _, err := r.lockChildren(`SELECT id::text,alert_id::text FROM public.`+table+` WHERE alert_id=ANY($1::bigint[]) ORDER BY id LIMIT 10001`, pq.Array(aids)); err != nil {
			return err
		}
	}
	subs, err := r.lockChildren(`SELECT id::text,alert_id::text,COALESCE(contact_method_id::text,''),COALESCE(channel_id::text,'') FROM public.alert_status_subscriptions WHERE alert_id=ANY($1::bigint[]) ORDER BY id LIMIT 10001`, pq.Array(aids))
	if err != nil {
		return err
	}
	favorites, err := r.lockChildren(`SELECT id::text,tgt_service_id::text,user_id::text FROM public.user_favorites WHERE tgt_service_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	// Messages and Signals have WARNING deletion policy, but the frozen D09
	// Service envelope cannot record their effects. Preserve them until a new
	// audit contract is approved; never delete them as generic owned children.
	messages, err := r.lockChildren(`SELECT id::text FROM public.outgoing_messages WHERE service_id=ANY($1::uuid[]) OR alert_id=ANY($2::bigint[]) OR cycle_id=ANY($3::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids), pq.Array(aids), pq.Array(column(cycles, 0)))
	if err != nil {
		return err
	}
	signals, err := r.lockChildren(`SELECT id::text FROM public.pending_signals WHERE service_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	if len(messages) != 0 || len(signals) != 0 {
		return unavailable()
	}
	// Historical status bundles lack an FK. The only current manager writing
	// bundles holds outgoing_messages EXCLUSIVE; our normal ROW SHARE conflicts.
	if err := r.tx.QueryRowContext(r.ctx, `SELECT EXISTS(SELECT FROM public.outgoing_messages WHERE status_alert_ids && $1::bigint[])`, pq.Array(aids)).Scan(&unsupported); err != nil || unsupported {
		return unavailable()
	}
	// AlertLog has no FK. All three real insertion queries take KEY SHARE on
	// the actual Alert and subject Key in their own statement/transaction. Our
	// UPDATE locks therefore freeze both existing and new incoming log edges.
	logs, err := r.lockChildren(`SELECT id::text,COALESCE(alert_id::text,'') FROM public.alert_logs WHERE alert_id=ANY($1::bigint[]) OR sub_integration_key_id IN (SELECT id FROM public.integration_keys WHERE audit_resource_id=ANY($2::uuid[])) ORDER BY id LIMIT 10001`, pq.Array(aids), pq.Array(column(keys, 0)))
	if err != nil {
		return err
	}
	externalAlerts := slices.DeleteFunc(mergeIDs(column(logs, 1)), func(id string) bool { return slices.Contains(aids, id) })
	parents, err := r.read(`SELECT id::text,COALESCE(service_id::text,'') FROM public.alerts WHERE id=ANY($1::bigint[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(externalAlerts))
	if err != nil {
		return err
	}
	if !slices.Equal(column(parents, 0), externalAlerts) {
		return unavailable()
	}
	if err := r.charge(parents); err != nil {
		return err
	}
	if err := r.lockServiceReferences(parents, subs); err != nil {
		return err
	}
	users := mergeIDs(column(cycles, 2), column(favorites, 2))
	cms, err := r.read(`SELECT id::text,user_id::text FROM public.user_contact_methods WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(mergeIDs(column(subs, 2))))
	if err != nil {
		return err
	}
	if !slices.Equal(column(cms, 0), mergeIDs(column(subs, 2))) {
		return unavailable()
	}
	if err := r.charge(cms); err != nil {
		return err
	}
	return r.lockServiceScope(mergeIDs(users, column(cms, 1)), column(roots, 1))
}

func (r *stableReader) lockServiceReferences(alerts, subs [][]string) error {
	for _, set := range []struct {
		query string
		ids   []string
	}{
		{`SELECT id::text FROM public.services WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, mergeIDs(column(alerts, 1))},
		{`SELECT id::text FROM public.notification_channels WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, mergeIDs(column(subs, 3))},
	} {
		rows, err := r.read(set.query, pq.Array(set.ids))
		if err != nil {
			return err
		}
		if !slices.Equal(column(rows, 0), set.ids) {
			return unavailable()
		}
		if err := r.charge(rows); err != nil {
			return err
		}
	}
	return nil
}

// Lock the actor and every scope-producing owner/assignment/organization.
// Service itself has an Organization, not a synthetic owning User.
func (r *stableReader) lockServiceScope(users, orgs []string) error {
	if !permission.System(r.ctx) {
		actor, err := uuid.Parse(permission.UserID(r.ctx))
		if err != nil || actor == uuid.Nil {
			return unavailable()
		}
		users = mergeIDs(users, []string{actor.String()})
	}
	locked, err := r.read(`SELECT id::text FROM public.users WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(users))
	if err != nil {
		return err
	}
	if !slices.Equal(column(locked, 0), users) {
		return unavailable()
	}
	assignments, err := r.read(`SELECT user_id::text,effective_organization_id::text,COALESCE(effective_normal_organization_id::text,'') FROM public.user_organization_assignments WHERE user_id=ANY($1::uuid[]) ORDER BY user_id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(users))
	if err != nil {
		return err
	}
	if !slices.Equal(column(assignments, 0), users) {
		return unavailable()
	}
	orgs = mergeIDs(orgs, column(assignments, 1))
	organizations, err := r.read(`SELECT id::text FROM public.organizations WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(orgs))
	if err != nil {
		return err
	}
	if !slices.Equal(column(organizations, 0), orgs) {
		return unavailable()
	}
	normalIDs := slices.DeleteFunc(column(assignments, 2), func(id string) bool { return strings.TrimSpace(id) == "" })
	normals, err := r.read(`SELECT organization_id::text FROM public.normal_organizations WHERE organization_id=ANY($1::uuid[]) ORDER BY organization_id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(normalIDs))
	if err != nil {
		return err
	}
	if !slices.Equal(column(normals, 0), normalIDs) {
		return unavailable()
	}
	for _, rows := range [][][]string{locked, assignments, organizations, normals} {
		if err := r.charge(rows); err != nil {
			return err
		}
	}
	fresh, err := r.read(`SELECT user_id::text,effective_organization_id::text,COALESCE(effective_normal_organization_id::text,'') FROM public.user_organization_assignments WHERE user_id=ANY($1::uuid[]) ORDER BY user_id`, pq.Array(users))
	if err != nil {
		return err
	}
	if !sameRows(fresh, assignments) {
		return unavailable()
	}
	return nil
}
