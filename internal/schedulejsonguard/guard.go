// Package schedulejsonguard carries a transaction-bound, exact JSON update
// capability from verified confirmation to the existing ScheduleData writer.
package schedulejsonguard

import (
	"context"
	"database/sql"
	"reflect"
	"slices"
	"sync/atomic"

	"github.com/google/uuid"
	ds "github.com/target/goalert/deletionsafety"
	audit "github.com/target/goalert/schedule/jsonupdateaudit"
)

type key struct{}
type grant struct {
	tx    *sql.Tx
	event audit.Event
	used  atomic.Bool
}

func Bound(ctx context.Context, tx *sql.Tx) bool {
	g, _ := ctx.Value(key{}).(*grant)
	return g != nil && g.tx == tx && !g.used.Load()
}

// Bind is internal-only. The caller must recheck current authority, locked
// business facts and signed consent before issuing this exact capability.
func Bind(ctx context.Context, tx *sql.Tx, e audit.Event) (context.Context, error) {
	if tx == nil || e.ScheduleID == uuid.Nil {
		return ctx, audit.ErrInvalid
	}
	// A missing envelope can acquire its real database identity during INSERT.
	check := e
	if check.EnvelopeID == 0 {
		check.EnvelopeID = 1
	}
	if err := check.Validate(); err != nil {
		return ctx, err
	}
	e.Before = slices.Clone(e.Before)
	e.After = slices.Clone(e.After)
	e.Effects = slices.Clone(e.Effects)
	return context.WithValue(ctx, key{}, &grant{tx: tx, event: e}), nil
}

func Destructive(effects []audit.Effect) bool {
	for _, e := range effects {
		if e.Change == "coverage_removed" {
			return true
		}
	}
	return false
}

// Authorize runs even for direct Store calls, after the locked fresh diff.
// A non-destructive legacy call needs no removal capability. All bound calls
// match the entire before/after, operation, mode, envelope and transaction.
func Authorize(ctx context.Context, tx *sql.Tx, id uuid.UUID, envelope int64, op, mode string, b, a []audit.Coverage) error {
	effects, err := audit.Diff(b, a)
	if err != nil {
		return err
	}
	g, _ := ctx.Value(key{}).(*grant)
	if g == nil {
		if Destructive(effects) {
			return &ds.DeletionSafetyError{Code: ds.DeletionConfirmationRequired}
		}
		return nil
	}
	e := g.event
	if g.tx != tx || g.used.Load() || e.ScheduleID != id || (e.EnvelopeID != 0 && e.EnvelopeID != envelope) || e.Operation != op || e.Mode != mode || !reflect.DeepEqual(e.Before, b) || !reflect.DeepEqual(e.After, a) || !reflect.DeepEqual(e.Effects, effects) {
		return &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
	}
	return nil
}

// Finish checks the actual stored result and appends inside the same writer
// savepoint/transaction. Background envelope writers do not call this adapter.
func Finish(ctx context.Context, tx *sql.Tx, id uuid.UUID, envelope int64, op, mode string, b, a []audit.Coverage) error {
	if err := Authorize(ctx, tx, id, envelope, op, mode, b, a); err != nil {
		return err
	}
	g, _ := ctx.Value(key{}).(*grant)
	if g == nil {
		return nil
	}
	if !g.used.CompareAndSwap(false, true) {
		return audit.ErrInvalid
	}
	e := g.event
	e.EnvelopeID = envelope
	if reflect.DeepEqual(e.Before, e.After) {
		return nil
	} // no duplicate/equivalent update facts
	return audit.Append(ctx, tx, e)
}
