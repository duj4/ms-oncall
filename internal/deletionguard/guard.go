// Package guard binds a checked server deletion plan to one live transaction.
// It owns neither authorization policy nor transaction finalization.
package guard

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"weak"

	"github.com/google/uuid"
	ds "github.com/target/goalert/deletionsafety"
)

type Selector struct {
	Kind ds.ResourceKind
	ID   string
}

const nrProfile = "notification-rule-only-v1"
const cmProfile = "contact-method-only-v1"
const serviceProfile = "service-only-v1"
const epProfile = "escalation-policy-only-v1"

type stabilityKey struct{}
type enforcementKey struct{}

// Epochs only revoke; they never prove locks. SQL rollback cannot restore an
// older epoch. Weak keys and cleanup do not retain ended transactions/contexts.
var epochs = struct {
	sync.Mutex
	values map[weak.Pointer[sql.Tx]]*atomic.Uint64
}{values: make(map[weak.Pointer[sql.Tx]]*atomic.Uint64)}

func nextEpoch(tx *sql.Tx) (*atomic.Uint64, uint64) {
	key := weak.Make(tx)
	epochs.Lock()
	defer epochs.Unlock()
	epoch := epochs.values[key]
	if epoch == nil {
		epoch = new(atomic.Uint64)
		epochs.values[key] = epoch
		runtime.AddCleanup(tx, func(key weak.Pointer[sql.Tx]) {
			epochs.Lock()
			delete(epochs.values, key)
			epochs.Unlock()
		}, key)
	}
	return epoch, epoch.Add(1)
}

type stability struct {
	bound                  atomic.Bool
	kind                   ds.ResourceKind
	profile                string
	tx                     *sql.Tx
	nonce                  uuid.UUID
	epoch                  *atomic.Uint64
	generation             uint64
	rawHash, effectiveHash [32]byte
	targets                []ds.Resource
}
type enforcementGuard struct {
	mu        sync.Mutex
	stable    *stability
	remaining map[Selector]bool
	ready     bool
}

func unavailable() error { return &ds.DeletionSafetyError{Code: ds.DeletionUnavailable} }
func digest[T any](value T) [32]byte {
	data, _ := json.Marshal(value) // fixed non-secret identity structs only
	return sha256.Sum256(data)
}

// The locked checkpoint is NOT executable proof. Bind creates the certified
// row only after final Collect/BuildPlan/Check. Rolling back across any lock
// removes the later checkpoint/certificate, including after table reuse.
const witnessDDL = `CREATE TEMP TABLE IF NOT EXISTS d09_nr_deletion_witness (
 nonce uuid NOT NULL, phase text NOT NULL, profile text NOT NULL,
 raw_hash bytea NOT NULL, effective_hash bytea NOT NULL, xid text NOT NULL,
 PRIMARY KEY(nonce,phase)
) ON COMMIT DROP`

func (s *stability) witness(ctx context.Context, tx *sql.Tx, phase string) bool {
	if s == nil || tx == nil || s.tx != tx || s.epoch == nil || s.epoch.Load() != s.generation {
		return false
	}
	// Rollback may remove the temp table; avoid aborting a usable transaction.
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('pg_temp.d09_nr_deletion_witness') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		return false
	}
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_temp.d09_nr_deletion_witness
 WHERE nonce=$1 AND phase=$2 AND profile=$3 AND raw_hash=$4 AND effective_hash=$5
 AND xid=pg_current_xact_id()::text)`, s.nonce, phase, s.profile, s.rawHash[:], s.effectiveHash[:]).Scan(&exists)
	return err == nil && exists
}

// StableNR permits READ COMMITTED only for existing selected NRs after the
// actual stabilization protocol in this transaction. It grants no deletion.
func StableNR(ctx context.Context, tx *sql.Tx, root ds.Resource) bool {
	if ctx == nil || root.Kind != ds.ResourceNotificationRule {
		return false
	}
	s, _ := ctx.Value(stabilityKey{}).(*stability)
	return s != nil && s.kind == root.Kind && slices.Contains(s.targets, root) && s.witness(ctx, tx, "locked")
}

// StableCM uses the same transactional checkpoint as NR, with an exact root
// profile. Owned NR cascades are facts, never an explicit NR Store capability.
func StableCM(ctx context.Context, tx *sql.Tx, root ds.Resource) bool {
	if ctx == nil || root.Kind != ds.ResourceContactMethod {
		return false
	}
	s, _ := ctx.Value(stabilityKey{}).(*stability)
	return s != nil && s.kind == root.Kind && slices.Contains(s.targets, root) && s.witness(ctx, tx, "locked")
}

// StableService accepts only this transaction's selected existing Service roots.
func StableService(ctx context.Context, tx *sql.Tx, root ds.Resource) bool {
	if ctx == nil || root.Kind != ds.ResourceService {
		return false
	}
	s, _ := ctx.Value(stabilityKey{}).(*stability)
	return s != nil && s.kind == root.Kind && s.profile == serviceProfile && slices.Contains(s.targets, root) && s.witness(ctx, tx, "locked")
}

// StableEP admits only the selected existing policies under the EP protocol.
func StableEP(ctx context.Context, tx *sql.Tx, root ds.Resource) bool {
	if ctx == nil || root.Kind != ds.ResourceEscalationPolicy {
		return false
	}
	s, _ := ctx.Value(stabilityKey{}).(*stability)
	return s != nil && s.kind == root.Kind && s.profile == epProfile && slices.Contains(s.targets, root) && s.witness(ctx, tx, "locked")
}

// Bind is called by the trusted enforcer after fresh authorization, collection
// and policy/version checks under the stable set. base keeps the request's
// cancellation; checked carries the bounded recheck context and checkpoint.
func Bind(base context.Context, tx *sql.Tx, checked context.Context, raw []Selector, plan ds.DeletionPlan, expected string, acknowledged bool) (context.Context, error) {
	if base == nil || checked == nil {
		return base, unavailable()
	}
	s, _ := checked.Value(stabilityKey{}).(*stability)
	if s == nil || digest(raw) != s.rawHash || !s.witness(checked, tx, "locked") || !slices.Equal(plan.Targets(), s.targets) {
		return base, unavailable()
	}
	if len(s.targets) > 0 {
		if err := plan.Check(expected, acknowledged); err != nil {
			return base, err
		}
	} else if expected != "" {
		return base, &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
	}
	for _, change := range plan.Changes() {
		if change.Cause == ds.CauseExplicit && change.Kind != ds.ChangeDeleted {
			return base, unavailable()
		}
	}
	if !s.bound.CompareAndSwap(false, true) {
		return base, unavailable()
	}
	if _, err := tx.ExecContext(checked, `INSERT INTO pg_temp.d09_nr_deletion_witness
 (nonce,phase,profile,raw_hash,effective_hash,xid) VALUES($1,'certified',$2,$3,$4,pg_current_xact_id()::text)`, s.nonce, s.profile, s.rawHash[:], s.effectiveHash[:]); err != nil {
		return base, unavailable()
	}
	g := &enforcementGuard{stable: s, remaining: make(map[Selector]bool), ready: true}
	for _, sel := range raw {
		id, err := uuid.Parse(sel.ID)
		if err != nil || sel.Kind != s.kind {
			return base, unavailable()
		}
		sel.ID = id.String()
		g.remaining[sel] = true
	}
	return context.WithValue(base, enforcementKey{}, g), nil
}

// ConsumeNR consumes the Store's original selectors once and returns only the
// certified existing, locked subset. Missing IDs cannot enter Store discovery
// or DELETE even if another transaction subsequently inserts those identities.
func ConsumeNR(ctx context.Context, tx *sql.Tx, ids []string) ([]string, error) {
	return consume(ctx, tx, ds.ResourceNotificationRule, ids)
}

// ConsumeCM returns only certified existing CM roots. Raw missing selectors must
// never be reintroduced by either the legacy or audited Store.
func ConsumeCM(ctx context.Context, tx *sql.Tx, ids []string) ([]string, error) {
	return consume(ctx, tx, ds.ResourceContactMethod, ids)
}

// ConsumeService prevents raw missing selectors from entering legacy or audited DML.
func ConsumeService(ctx context.Context, tx *sql.Tx, ids []string) ([]string, error) {
	return consume(ctx, tx, ds.ResourceService, ids)
}

// ConsumeEP never grants a separate Step, Action, or retained-target capability.
func ConsumeEP(ctx context.Context, tx *sql.Tx, ids []string) ([]string, error) {
	return consume(ctx, tx, ds.ResourceEscalationPolicy, ids)
}

// EPTargets keeps original D09 scope/capture on the certified existing subset.
func EPTargets(ctx context.Context, tx *sql.Tx, ids []string) ([]string, error) {
	return certifiedTargets(ctx, tx, ds.ResourceEscalationPolicy, ids, false)
}

// RequireDelete preserves all nine root Store boundaries. Other profiles fail
// closed, including System and direct Go calls. CM/NR Stores use ConsumeCM/NR.
func RequireDelete(ctx context.Context, tx *sql.Tx, kind ds.ResourceKind, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if kind != ds.ResourceNotificationRule && kind != ds.ResourceContactMethod {
		return unavailable()
	}
	_, err := consume(ctx, tx, kind, ids)
	return err
}

// ServiceTargets is a non-consuming projection for the original D09 capture.
// Capture and Store must use the same certified subset, even if a raw Missing
// UUID is inserted between certification and the first capture query.
func ServiceTargets(ctx context.Context, tx *sql.Tx, ids []string) ([]string, error) {
	return certifiedTargets(ctx, tx, ds.ResourceService, ids, false)
}

func consume(ctx context.Context, tx *sql.Tx, kind ds.ResourceKind, ids []string) ([]string, error) {
	return certifiedTargets(ctx, tx, kind, ids, true)
}

func certifiedTargets(ctx context.Context, tx *sql.Tx, kind ds.ResourceKind, ids []string, consumeSelection bool) ([]string, error) {
	if ctx == nil || tx == nil || (kind != ds.ResourceNotificationRule && kind != ds.ResourceContactMethod && kind != ds.ResourceService && kind != ds.ResourceEscalationPolicy) {
		return nil, unavailable()
	}
	g, _ := ctx.Value(enforcementKey{}).(*enforcementGuard)
	if g == nil {
		return nil, unavailable()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.ready || g.stable.tx != tx || g.stable.kind != kind {
		return nil, unavailable()
	}
	if !g.stable.witness(ctx, tx, "certified") {
		g.ready = false
		return nil, unavailable()
	}
	unique := make(map[Selector]bool)
	for _, id := range ids {
		parsed, err := uuid.Parse(id)
		if err != nil {
			return nil, unavailable()
		}
		sel := Selector{Kind: kind, ID: parsed.String()}
		if !g.remaining[sel] {
			return nil, unavailable()
		}
		unique[sel] = true
	}
	var effective []string
	for _, target := range g.stable.targets {
		if unique[Selector{Kind: target.Kind, ID: target.ID}] {
			effective = append(effective, target.ID)
		}
	}
	if consumeSelection {
		for sel := range unique {
			delete(g.remaining, sel)
		}
	}
	return effective, nil
}
