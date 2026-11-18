// Package oncalljsonguard binds the approved semantic diff to one transaction
// and one consumption by the existing ScheduleData writer.
package oncalljsonguard

import (
	"context"
	"database/sql"
	"reflect"
	"slices"
	"sync/atomic"

	"github.com/google/uuid"
	ds "github.com/target/goalert/deletionsafety"
	audit "github.com/target/goalert/schedule/oncallupdateaudit"
)

type key struct{}
type grant struct {
	tx    *sql.Tx
	event audit.Event
	used  atomic.Bool
}

func Bind(ctx context.Context, tx *sql.Tx, e audit.Event) (context.Context, error) {
	check := e
	if check.EnvelopeID == 0 {
		check.EnvelopeID = 1
	}
	if tx == nil || check.Validate() != nil {
		return ctx, audit.ErrInvalid
	}
	e.Before = slices.Clone(e.Before)
	e.After = slices.Clone(e.After)
	e.Effects = slices.Clone(e.Effects)
	return context.WithValue(ctx, key{}, &grant{tx: tx, event: e}), nil
}

func Authorize(ctx context.Context, tx *sql.Tx, id, org uuid.UUID, envelope int64, b, a []audit.Rule) error {
	effects, err := audit.Diff(id, b, a)
	if err != nil {
		return err
	}
	g, _ := ctx.Value(key{}).(*grant)
	if g == nil {
		if audit.Destructive(effects) {
			return &ds.DeletionSafetyError{Code: ds.DeletionConfirmationRequired}
		}
		return nil
	}
	e := g.event
	if g.tx != tx || g.used.Load() || e.ScheduleID != id || e.OrganizationID != org || e.Operation != audit.Operation || e.EnvelopeID != 0 && e.EnvelopeID != envelope || !audit.Equal(e.Before, b) || !audit.Equal(e.After, a) || !reflect.DeepEqual(e.Effects, effects) {
		return &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
	}
	return nil
}

func Finish(ctx context.Context, tx *sql.Tx, id, org uuid.UUID, envelope int64, b, a []audit.Rule) error {
	if err := Authorize(ctx, tx, id, org, envelope, b, a); err != nil {
		return err
	}
	g, _ := ctx.Value(key{}).(*grant)
	if g == nil {
		return nil
	}
	if !g.used.CompareAndSwap(false, true) {
		return audit.ErrInvalid
	}
	if audit.Equal(b, a) {
		return nil
	}
	e := g.event
	e.EnvelopeID = envelope
	return audit.Append(ctx, tx, e)
}
