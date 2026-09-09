package executioncontext

import (
	"context"
	"net/http"

	"github.com/target/goalert/auth"
)

type executionContextKey struct{}

// WithExecutionContext returns a context carrying a defensive copy of a valid
// request-bound ExecutionContext. Invalid values are not installed.
func WithExecutionContext(ctx context.Context, value ExecutionContext) context.Context {
	if ctx == nil || !value.Valid() {
		return ctx
	}
	return context.WithValue(ctx, executionContextKey{}, value)
}

// ExecutionContextFromContext returns a defensive copy of the request-bound
// ExecutionContext. Missing, invalid, and nil contexts return nil.
func ExecutionContextFromContext(ctx context.Context) *ExecutionContext {
	if ctx == nil {
		return nil
	}
	value, ok := ctx.Value(executionContextKey{}).(ExecutionContext)
	if !ok || !value.Valid() {
		return nil
	}
	return &value
}

// WrapHandler constructs ordinary-human authority immediately after canonical
// authentication. Requests without a typed human Requester, or whose current
// local authority is unavailable, continue without an ExecutionContext.
func (c *HumanExecutionContextConstructor) WrapHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// This wrapper is the canonical producer for the request. Shadow any
		// inherited authority before reconstructing current local authority.
		ctx := context.WithValue(req.Context(), executionContextKey{}, ExecutionContext{})
		req = req.WithContext(ctx)

		if auth.RequesterFromContext(ctx) == nil {
			next.ServeHTTP(w, req)
			return
		}

		value, err := c.Construct(ctx)
		if err != nil || !value.Valid() {
			next.ServeHTTP(w, req)
			return
		}

		next.ServeHTTP(w, req.WithContext(WithExecutionContext(ctx, value)))
	})
}
