// Package updateguard confines SD10 child deletion to the transaction and exact
// identities freshly checked by the update owner. It grants no root deletion.
package updateguard

import (
	"context"
	"database/sql"
	"sync"

	ds "github.com/target/goalert/deletionsafety"
)

type key struct{}
type capability struct {
	mu        sync.Mutex
	tx        *sql.Tx
	remaining map[ds.Resource]bool
}

func unavailable() error { return &ds.DeletionSafetyError{Code: ds.DeletionUnavailable} }

// Bind is called only by the trusted owner after locking, planning and checking
// confirmation. The context never leaves that owner's callback. Stores cannot
// create a capability and a wire Boolean cannot authorize a Store operation.
func Bind(ctx context.Context, tx *sql.Tx, resources []ds.Resource) (context.Context, error) {
	if ctx == nil || tx == nil || len(resources) == 0 {
		return ctx, unavailable()
	}
	c := &capability{tx: tx, remaining: make(map[ds.Resource]bool)}
	for _, r := range resources {
		if r.ID == "" || (r.Kind != ds.ResourceEscalationPolicyStep && r.Kind != ds.ResourceEscalationPolicyAction && r.Kind != ds.ResourceScheduleRule) || c.remaining[r] {
			return ctx, unavailable()
		}
		c.remaining[r] = true
	}
	return context.WithValue(ctx, key{}, c), nil
}

// Require fails before DML when no transaction-bound owner exists. Actual
// RETURNING identities are then consumed, and the owner verifies completeness.
func Require(ctx context.Context, tx *sql.Tx) error {
	if ctx == nil || tx == nil {
		return unavailable()
	}
	c, _ := ctx.Value(key{}).(*capability)
	if c == nil || c.tx != tx {
		return unavailable()
	}
	return nil
}

func Consume(ctx context.Context, tx *sql.Tx, resources ...ds.Resource) error {
	if err := Require(ctx, tx); err != nil {
		return err
	}
	c := ctx.Value(key{}).(*capability)
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := make(map[ds.Resource]bool)
	for _, r := range resources {
		if !c.remaining[r] || seen[r] {
			return unavailable()
		}
		seen[r] = true
	}
	for _, r := range resources {
		delete(c.remaining, r)
	}
	return nil
}

func Complete(ctx context.Context, tx *sql.Tx) error {
	if err := Require(ctx, tx); err != nil {
		return err
	}
	c := ctx.Value(key{}).(*capability)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.remaining) != 0 {
		return unavailable()
	}
	return nil
}
