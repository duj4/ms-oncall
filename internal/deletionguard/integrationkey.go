package guard

import (
	"context"
	"database/sql"
	"slices"

	"github.com/google/uuid"
	"github.com/lib/pq"
	ds "github.com/target/goalert/deletionsafety"
)

const integrationKeyProfile = "integration-key-only-v1"

// StabilizeIntegrationKey keeps credential selectors private. Only the existing
// SD4 audit identity enters targets, the plan, and the effective witness hash.
// Every lock after a Key lock is NOWAIT: real status writers can hold an Alert
// before requesting the Key, and Service deletion holds the parent first.
func StabilizeIntegrationKey(ctx context.Context, tx *sql.Tx, raw []Selector) (context.Context, []ds.Resource, error) {
	if ctx == nil || tx == nil || len(raw) == 0 || len(raw) > 50 {
		return ctx, nil, unavailable()
	}
	s := &stability{tx: tx, nonce: uuid.New(), rawHash: digest(raw), kind: ds.ResourceIntegrationKey, profile: integrationKeyProfile, keySelectors: make(map[string]string)}
	s.epoch, s.generation = nextEpoch(tx)
	var ids []string
	for _, sel := range raw {
		id, err := uuid.Parse(sel.ID)
		if err != nil || sel.Kind != s.kind {
			return ctx, nil, unavailable()
		}
		ids = append(ids, id.String())
	}
	ids = mergeIDs(ids)
	r := stableReader{ctx: ctx, tx: tx}
	const query = `SELECT audit_resource_id::text,service_id::text,type::text FROM public.integration_keys WHERE id=ANY($1::uuid[]) ORDER BY audit_resource_id LIMIT 10001`
	roots, err := r.lockChildren(query, pq.Array(ids))
	if err != nil {
		return ctx, nil, err
	}
	parents := column(roots, 1)
	services, err := r.read(`SELECT id::text,organization_id::text FROM public.services WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(parents))
	if err != nil || !slices.Equal(column(services, 0), parents) {
		return ctx, nil, unavailable()
	}
	if err = r.charge(services); err != nil {
		return ctx, nil, err
	}
	// The immediate config FK waits for our Key UPDATE lock. No unsupported
	// config is ever silently authorized by its database CASCADE behavior.
	var config bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM public.uik_config c JOIN public.integration_keys k ON k.id=c.id WHERE k.audit_resource_id=ANY($1::uuid[]))`, pq.Array(column(roots, 0))).Scan(&config); err != nil || config {
		return ctx, nil, unavailable()
	}
	// All three production log INSERT statements take KEY SHARE on the subject
	// Key. Lock existing history against cleanup, then corroborate its real Alert
	// and Service scope. No message, metadata, name or credential is projected.
	logs, err := r.read(`SELECT l.id::text,COALESCE(l.alert_id::text,'') FROM public.alert_logs l JOIN public.integration_keys k ON k.id=l.sub_integration_key_id WHERE k.audit_resource_id=ANY($1::uuid[]) ORDER BY l.id LIMIT 10001 FOR SHARE OF l NOWAIT`, pq.Array(column(roots, 0)))
	if err != nil {
		return ctx, nil, err
	}
	alerts, err := r.read(`SELECT id::text,COALESCE(service_id::text,'') FROM public.alerts WHERE id=ANY($1::bigint[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(column(logs, 1)))
	if err != nil || !slices.Equal(column(alerts, 0), column(logs, 1)) {
		return ctx, nil, unavailable()
	}
	historyServices, err := r.read(`SELECT id::text,organization_id::text FROM public.services WHERE id=ANY($1::uuid[]) ORDER BY id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(column(alerts, 1)))
	if err != nil || !slices.Equal(column(historyServices, 0), column(alerts, 1)) {
		return ctx, nil, unavailable()
	}
	for _, rows := range [][][]string{logs, alerts, historyServices} {
		if err = r.charge(rows); err != nil {
			return ctx, nil, err
		}
	}
	if err = r.lockServiceScope(nil, mergeIDs(column(services, 1), column(historyServices, 1))); err != nil {
		return ctx, nil, err
	}
	// System has no actor assignment from which lockServiceScope could derive
	// Normal subtypes. Lock the actual parents' subtypes too, before SD4 capture.
	normals, err := r.read(`SELECT organization_id::text FROM public.normal_organizations WHERE organization_id=ANY($1::uuid[]) ORDER BY organization_id LIMIT 10001 FOR SHARE NOWAIT`, pq.Array(mergeIDs(column(services, 1), column(historyServices, 1))))
	if err != nil {
		return ctx, nil, err
	}
	if err = r.charge(normals); err != nil {
		return ctx, nil, err
	}
	// Fresh RC facts after every scope lock. Include missing selectors in this
	// comparison; a later insertion stays outside the certified mapping forever.
	fresh, err := r.read(query, pq.Array(ids))
	if err != nil || !sameRows(roots, fresh) {
		return ctx, nil, unavailable()
	}
	for _, row := range roots {
		var credential string
		// This is a private SQL predicate mapping, never a resource projection.
		if err = tx.QueryRowContext(ctx, `SELECT id::text FROM public.integration_keys WHERE audit_resource_id=$1 AND id=ANY($2::uuid[]) AND id<>audit_resource_id AND id<>'00000000-0000-0000-0000-000000000000'::uuid AND audit_resource_id<>'00000000-0000-0000-0000-000000000000'::uuid`, row[0], pq.Array(ids)).Scan(&credential); err != nil {
			return ctx, nil, unavailable()
		}
		s.keySelectors[row[0]] = credential
		s.targets = append(s.targets, ds.Resource{Kind: s.kind, ID: row[0]})
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

func StableIntegrationKey(ctx context.Context, tx *sql.Tx, root ds.Resource) bool {
	if ctx == nil || root.Kind != ds.ResourceIntegrationKey {
		return false
	}
	s, _ := ctx.Value(stabilityKey{}).(*stability)
	return s != nil && s.kind == root.Kind && s.profile == integrationKeyProfile && slices.Contains(s.targets, root) && s.witness(ctx, tx, "locked")
}

// IntegrationKeyTargets returns private predicates only for certified existing
// identities. The controller uses this before scope and SD4 capture.
func IntegrationKeyTargets(ctx context.Context, tx *sql.Tx, ids []string) ([]string, error) {
	return certifiedTargets(ctx, tx, ds.ResourceIntegrationKey, ids, false)
}

func ConsumeIntegrationKey(ctx context.Context, tx *sql.Tx, ids []string) ([]string, error) {
	return consume(ctx, tx, ds.ResourceIntegrationKey, ids)
}
