package guard

import (
	"context"
	"database/sql"
	"slices"

	"github.com/google/uuid"
	"github.com/lib/pq"
	ds "github.com/target/goalert/deletionsafety"
)

// StabilizeSchedule freezes only existing selected roots and their real closure.
// Root UPDATE conflicts with every incoming immediate FK, including a previously
// absent JSON envelope. Existing children need their own UPDATE locks: changing
// a non-key column does not recheck the parent FK. Every lock is NOWAIT; Engine
// and Cleanup can hold the envelope before they touch the root or history.
func StabilizeSchedule(ctx context.Context, tx *sql.Tx, raw []Selector) (context.Context, []ds.Resource, error) {
	if ctx == nil || tx == nil || len(raw) == 0 || len(raw) > 50 {
		return ctx, nil, unavailable()
	}
	s := &stability{tx: tx, nonce: uuid.New(), rawHash: digest(raw), kind: ds.ResourceSchedule, profile: scheduleProfile}
	s.epoch, s.generation = nextEpoch(tx)
	var ids []string
	for _, sel := range raw {
		id, err := uuid.Parse(sel.ID)
		if err != nil || sel.Kind != ds.ResourceSchedule {
			return ctx, nil, unavailable()
		}
		ids = append(ids, id.String())
	}
	ids = mergeIDs(ids)
	// Ordinary locking-SELECT relation modes, before roots. The existing EP
	// Step and Override triggers and Message Manager request EXCLUSIVE first.
	// Do not wait for those relation locks while retaining a parent row.
	if _, err := tx.ExecContext(ctx, `LOCK TABLE public.escalation_policy_steps,public.user_overrides,public.outgoing_messages IN ROW SHARE MODE NOWAIT`); err != nil {
		return ctx, nil, unavailable()
	}
	r := stableReader{ctx: ctx, tx: tx}
	roots, err := r.lockChildren(`SELECT id::text,organization_id::text FROM public.schedules WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return ctx, nil, err
	}
	for _, row := range roots {
		s.targets = append(s.targets, ds.Resource{Kind: ds.ResourceSchedule, ID: row[0]})
	}
	if err := r.lockScheduleClosure(roots); err != nil {
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

func (r *stableReader) lockScheduleClosure(roots [][]string) error {
	ids := column(roots, 0)
	actions, err := r.lockChildren(`SELECT id::text,escalation_policy_step_id::text,schedule_id::text FROM public.escalation_policy_actions WHERE schedule_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	// Retain Actions and their actual parents. The unchanged Collector/Planner
	// reports BLOCK, including multiple policies, steps, and actions. Deletion
	// never detaches them, even with a matching version and confirmation.
	steps, err := r.read(`SELECT id::text,escalation_policy_id::text FROM public.escalation_policy_steps WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(column(actions, 1)))
	if err != nil || !slices.Equal(column(steps, 0), column(actions, 1)) {
		return unavailable()
	}
	policies, err := r.read(`SELECT id::text,organization_id::text FROM public.escalation_policies WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(column(steps, 1)))
	if err != nil || !slices.Equal(column(policies, 0), column(steps, 1)) {
		return unavailable()
	}
	rules, err := r.lockChildren(`SELECT id::text,schedule_id::text,COALESCE(tgt_user_id::text,''),COALESCE(tgt_rotation_id::text,'') FROM public.schedule_rules WHERE schedule_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	overrides, err := r.lockChildren(`SELECT id::text,tgt_schedule_id::text,COALESCE(add_user_id::text,''),COALESCE(remove_user_id::text,''),start_time::text,end_time::text FROM public.user_overrides WHERE tgt_schedule_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	for _, o := range overrides {
		// Frozen B2 cannot express a malformed override with equal endpoints.
		if o[2] == o[3] {
			return unavailable()
		}
	}
	// Lock the envelope, never a normalized/filtered Schedule getter. Final
	// Collect uses IMPL2's raw bounded JSON parser, times and stored ordinals.
	envelopes, err := r.lockChildren(`SELECT id::text,schedule_id::text,(octet_length(data::text)<=1048576)::text FROM public.schedule_data WHERE schedule_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	for _, row := range envelopes {
		if row[2] != "true" {
			return unavailable()
		}
	}
	favorites, err := r.lockChildren(`SELECT id::text,tgt_schedule_id::text,user_id::text FROM public.user_favorites WHERE tgt_schedule_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	// History must survive. Messages lack an approved Schedule B2 effect.
	// Root UPDATE fences new incoming rows; existing membership is rechecked.
	for _, query := range []string{
		`SELECT id::text FROM public.schedule_on_call_users WHERE schedule_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`,
		`SELECT id::text FROM public.outgoing_messages WHERE schedule_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`,
	} {
		rows, err := r.lockChildren(query, pq.Array(ids))
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			return unavailable()
		}
	}
	rotations, err := r.read(`SELECT id::text,organization_id::text FROM public.rotations WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(mergeIDs(column(rules, 3))))
	if err != nil || !slices.Equal(column(rotations, 0), mergeIDs(column(rules, 3))) {
		return unavailable()
	}
	// Extract only candidate UUID identities from already locked raw JSON. This
	// is not validation or dependency discovery: malformed/missing/unknown JSON
	// is rejected by the full, unchanged Collector before certification.
	jsonIDs, err := r.read(`SELECT DISTINCT CASE WHEN v#>>'{}' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (v#>>'{}')::uuid::text ELSE '' END AS id,'user' AS kind FROM public.schedule_data d CROSS JOIN LATERAL jsonb_path_query(d.data,'$.V1.TemporarySchedules[*].Shifts[*].UserID') v WHERE d.schedule_id=ANY($1::uuid[])
 UNION SELECT DISTINCT CASE WHEN v#>>'{}' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN (v#>>'{}')::uuid::text ELSE '' END,'channel' FROM public.schedule_data d CROSS JOIN LATERAL jsonb_path_query(d.data,'$.V1.OnCallNotificationRules[*].ChannelID') v WHERE d.schedule_id=ANY($1::uuid[]) ORDER BY 1,2 LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return err
	}
	var users, channels []string
	for _, row := range jsonIDs {
		if row[1] == "user" {
			users = append(users, row[0])
		} else {
			channels = append(channels, row[0])
		}
	}
	channels = mergeIDs(channels)
	lockedChannels, err := r.read(`SELECT id::text FROM public.notification_channels WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(channels))
	if err != nil || !slices.Equal(column(lockedChannels, 0), channels) {
		return unavailable()
	}
	for _, rows := range [][][]string{steps, policies, rotations, jsonIDs, lockedChannels} {
		if err := r.charge(rows); err != nil {
			return err
		}
	}
	// Rotation participants/state are retained and are not inputs to this
	// deletion plan. Do not lock an unrelated runtime/Collector read-set.
	return r.lockServiceScope(mergeIDs(users, column(rules, 2), column(overrides, 2), column(overrides, 3), column(favorites, 2)), mergeIDs(column(roots, 1), column(policies, 1), column(rotations, 1)))
}
