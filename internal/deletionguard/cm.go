package guard

import (
	"context"
	"database/sql"
	"slices"

	"github.com/lib/pq"
	ds "github.com/target/goalert/deletionsafety"
)

// StabilizeCM extends the existing owner-level protocol. All CM-specific
// conflicting locks use NOWAIT: verification/engine writers may lock a child
// before its parent. We never wait in that reverse order or assume that an
// advisory lock used only by deletion coordinates those writers.
func StabilizeCM(ctx context.Context, tx *sql.Tx, raw []Selector) (context.Context, []ds.Resource, error) {
	return stabilizeOwner(ctx, tx, raw, ds.ResourceContactMethod)
}

func mergeIDs(sets ...[]string) []string {
	var ids []string
	for _, set := range sets {
		for _, id := range set {
			if id != "" {
				ids = append(ids, id)
			}
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

type cmClosure struct {
	alerts, statusUsers []string
	messages, signals   [][]string
}

// Parents already have UPDATE locks. Immediate FK writers cannot enter these
// sets; an existing child must itself be locked, including deletes/retargets.
// Each lock query is followed by a NEW RC membership/parent comparison.
func (r *stableReader) lockChildren(query string, args ...any) ([][]string, error) {
	rows, err := r.read(query+` FOR UPDATE NOWAIT`, args...)
	if err != nil {
		return nil, err
	}
	if err = r.charge(rows); err != nil {
		return nil, err
	}
	fresh, err := r.read(query, args...)
	if err != nil || !sameRows(rows, fresh) {
		return nil, unavailable()
	}
	return rows, nil
}

func (r *stableReader) lockCMClosure(ids []string, owners map[string]string, nrs [][]string) (cmClosure, error) {
	var c cmClosure
	// Include ALL actual incoming NRs, even malformed cross-owner references.
	// Such a row must not escape the owner's stable set and be cascaded unseen.
	owned, err := r.read(`SELECT id::text,user_id::text,contact_method_id::text FROM public.user_notification_rules WHERE contact_method_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return c, err
	}
	for _, row := range owned {
		if owners[row[2]] != row[1] || !slices.ContainsFunc(nrs, func(n []string) bool { return slices.Equal(n, row) }) {
			return c, unavailable()
		}
	}
	codes, err := r.lockChildren(`SELECT id::text,contact_method_id::text FROM public.user_verification_codes WHERE contact_method_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return c, err
	}
	subjects, err := r.lockChildren(`SELECT id::text,user_id::text,cm_id::text FROM public.auth_subjects WHERE cm_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return c, err
	}
	for _, row := range subjects {
		if owners[row[2]] != row[1] {
			return c, unavailable()
		}
	}
	status, err := r.lockChildren(`SELECT id::text,alert_status_log_contact_method_id::text FROM public.users WHERE alert_status_log_contact_method_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return c, err
	}
	c.statusUsers = column(status, 0)
	subs, err := r.lockChildren(`SELECT id::text,contact_method_id::text,alert_id::text FROM public.alert_status_subscriptions WHERE contact_method_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids))
	if err != nil {
		return c, err
	}
	// Only safe identities are read. No code, subject, destination, payload,
	// provider/status text or private identity enters this checkpoint.
	c.messages, err = r.lockChildren(`SELECT id::text,COALESCE(contact_method_id::text,''),COALESCE(user_id::text,''),COALESCE(user_verification_code_id::text,''),COALESCE(cycle_id::text,''),COALESCE(alert_id::text,''),COALESCE(alert_log_id::text,''),COALESCE(service_id::text,''),COALESCE(schedule_id::text,''),COALESCE(escalation_policy_id::text,''),CASE WHEN message_type IN ('alert_notification_bundle','alert_status_update_bundle') OR last_status='bundled' THEN 'unsupported' ELSE '' END FROM public.outgoing_messages WHERE contact_method_id=ANY($1::uuid[]) OR user_verification_code_id=ANY($2::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(ids), pq.Array(column(codes, 0)))
	if err != nil {
		return c, err
	}
	for _, m := range c.messages {
		// Cross-CM verification references have no proved CM-only closure here.
		// Preserve the real row and fail closed rather than dropping that edge.
		if m[10] != "" || !slices.Contains(ids, m[1]) || owners[m[1]] != m[2] || m[3] != "" && !slices.Contains(column(codes, 0), m[3]) {
			return c, unavailable()
		}
	}
	// Bundling/dedup has no accepted V1 edge for status_details -> message.
	// Its actual writer (message.DB._SendMessages/currentQueue) first holds EXCLUSIVE
	// on outgoing_messages in the same transaction. Our existing ROW SHARE from
	// the lock query conflicts with that protocol, stabilizing this negative
	// observation too. No unilateral advisory lock or new global fence is used.
	var incomingBundle bool
	if err = r.tx.QueryRowContext(r.ctx, `SELECT EXISTS(SELECT FROM public.outgoing_messages WHERE last_status='bundled' AND status_details=ANY($1::text[]))`, pq.Array(column(c.messages, 0))).Scan(&incomingBundle); err != nil || incomingBundle {
		return c, unavailable()
	}
	c.signals, err = r.lockChildren(`SELECT id::text,service_id::text,dest_id::text,message_id::text FROM public.pending_signals WHERE message_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(column(c.messages, 0)))
	if err != nil {
		return c, err
	}
	if _, err = r.lockChildren(`SELECT id::text,message_id::text FROM public.message_status_history WHERE message_id=ANY($1::uuid[]) ORDER BY id LIMIT 10001`, pq.Array(column(c.messages, 0))); err != nil {
		return c, err
	}
	c.alerts = mergeIDs(column(subs, 2), column(c.messages, 5))
	// A message log also contributes its actual alert and service scope, even if
	// the message's own alert_id is NULL or references another alert.
	logs, err := r.read(`SELECT id::text,COALESCE(alert_id::text,'') FROM public.alert_logs WHERE id=ANY($1::bigint[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(mergeIDs(column(c.messages, 6))))
	if err != nil || !slices.Equal(column(logs, 0), mergeIDs(column(c.messages, 6))) {
		return c, unavailable()
	}
	if err = r.charge(logs); err != nil {
		return c, err
	}
	c.alerts = mergeIDs(c.alerts, column(logs, 1))
	return c, nil
}

func (r *stableReader) lockCMReferences(c cmClosure, cycles, alerts [][]string) error {
	for _, id := range mergeIDs(column(c.messages, 4)) {
		if !slices.Contains(column(cycles, 0), id) {
			return unavailable()
		}
	}
	// Alerts are retained. Their service parent and every scope-producing
	// message/signal reference must be stable before final Collector validation.
	alertParents, err := r.read(`SELECT id::text,service_id::text FROM public.alerts WHERE id=ANY($1::bigint[]) ORDER BY id LIMIT 10001`, pq.Array(column(alerts, 0)))
	if err != nil || !slices.Equal(column(alertParents, 0), column(alerts, 0)) {
		return unavailable()
	}
	for _, set := range []struct {
		query string
		ids   []string
	}{
		{`SELECT id::text FROM public.services WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, mergeIDs(column(alertParents, 1), column(c.messages, 7), column(c.signals, 1))},
		{`SELECT id::text FROM public.schedules WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, mergeIDs(column(c.messages, 8))},
		{`SELECT id::text FROM public.escalation_policies WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, mergeIDs(column(c.messages, 9))},
		{`SELECT id::text FROM public.notification_channels WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, mergeIDs(column(c.signals, 2))},
	} {
		rows, err := r.read(set.query, pq.Array(set.ids))
		if err != nil || !slices.Equal(column(rows, 0), set.ids) {
			return unavailable()
		}
		if err = r.charge(rows); err != nil {
			return err
		}
	}
	return nil
}
