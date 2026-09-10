// Package executioncontextvalue owns the dependency-neutral context slot for
// the validated request-bound ExecutionContext.
package executioncontextvalue

import (
	"context"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

// Value is the immutable Organization-authority surface consumed by lower
// level business stores. The concrete value installed by request admission is
// executioncontext.ExecutionContext.
type Value interface {
	Valid() bool
	EffectiveOrganizationID() (uuid.UUID, bool)
}

type contextKey struct{}

// With returns a context carrying value. Invalid values are not installed.
func With(ctx context.Context, value Value) context.Context {
	if ctx == nil || value == nil || !value.Valid() {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, value)
}

// Without shadows any inherited value.
func Without(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, contextKey{}, struct{}{})
}

// FromContext returns the validated authority surface stored in ctx.
func FromContext(ctx context.Context) Value {
	if ctx == nil {
		return nil
	}
	value, ok := ctx.Value(contextKey{}).(Value)
	if !ok || value == nil || !value.Valid() {
		return nil
	}
	return value
}

// EffectiveOrganizationID returns the non-Default effective Organization from
// the request-bound value. Missing, invalid, global, and Default authority all
// fail closed.
func EffectiveOrganizationID(ctx context.Context) (uuid.UUID, bool) {
	value := FromContext(ctx)
	if value == nil {
		return uuid.Nil, false
	}
	organizationID, present := value.EffectiveOrganizationID()
	if !present || organizationID == uuid.Nil || organizationID.String() == organization.DefaultOrganizationID {
		return uuid.Nil, false
	}
	return organizationID, true
}
