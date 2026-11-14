package graphqlapp

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/99designs/gqlgen/graphql"
	"github.com/google/uuid"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/util/log"
)

type sessionDiagnosticKey struct{}

func WithUserSessionLogState(ctx context.Context) (context.Context, *atomic.Bool) {
	state := new(atomic.Bool)
	return context.WithValue(ctx, sessionDiagnosticKey{}, state), state
}
func sessionInputSelected(v any) bool {
	switch v := v.(type) {
	case []any:
		for _, item := range v {
			if sessionInputSelected(item) {
				return true
			}
		}
	case map[string]any:
		kind, ok := v["type"]
		if !ok {
			return true
		}
		switch kind := kind.(type) {
		case string:
			return kind == "userSession"
		case assignment.TargetType:
			return kind == assignment.TargetTypeUserSession
		default:
			return true
		}
	case []assignment.RawTarget:
		for _, t := range v {
			if t.TargetType() == assignment.TargetTypeUserSession {
				return true
			}
		}
	default:
		return true
	}
	return false
}
func sessionDiagnosticOperation(ctx context.Context) bool {
	if !graphql.HasOperationContext(ctx) {
		return false
	}
	op := graphql.GetOperationContext(ctx)
	if op.Operation == nil {
		return true
	}
	for _, f := range graphql.CollectFields(op, op.Operation.SelectionSet, []string{"Mutation"}) {
		if f.Name == "endAllAuthSessionsByCurrentUser" {
			return true
		}
		if f.Name == "deleteAll" {
			arg := f.Arguments.ForName("input")
			if arg == nil {
				return true
			}
			value, err := arg.Value.Value(op.Variables)
			if err != nil || sessionInputSelected(value) {
				return true
			}
		}
	}
	return false
}
func sessionDiagnosticSelected(ctx context.Context) bool {
	if s, ok := ctx.Value(sessionDiagnosticKey{}).(*atomic.Bool); ok && s.Load() {
		return true
	}
	return sessionDiagnosticOperation(ctx)
}
func selectSessionDiagnostics(ctx context.Context) {
	if sessionDiagnosticOperation(ctx) {
		if s, ok := ctx.Value(sessionDiagnosticKey{}).(*atomic.Bool); ok {
			s.Store(true)
		}
	}
}
func sessionDiagnosticContext(ctx context.Context) context.Context {
	if !sessionDiagnosticSelected(ctx) {
		return ctx
	}
	clean := log.FromContext(ctx).BackgroundContext()
	clean = log.WithField(clean, "DiagnosticPolicy", "graphql_closed_projection")
	if id, err := uuid.Parse(log.RequestID(ctx)); err == nil && id != uuid.Nil {
		clean = log.WithField(clean, "RequestID", id.String())
	}
	return clean
}
func sessionDiagnosticError(ctx context.Context, err error) error {
	if err != nil && sessionDiagnosticSelected(ctx) {
		return errors.New("GraphQL operation failed")
	}
	return err
}
