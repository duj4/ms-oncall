package executioncontext

import (
	"context"
	"net/http"

	"github.com/target/goalert/auth"
	"github.com/target/goalert/internal/executioncontextvalue"
)

// WithExecutionContext returns a context carrying a defensive copy of a valid
// request-bound ExecutionContext. Invalid values are not installed.
func WithExecutionContext(ctx context.Context, value ExecutionContext) context.Context {
	if ctx == nil || !value.Valid() {
		return ctx
	}
	return executioncontextvalue.With(ctx, &value)
}

// ExecutionContextFromContext returns a defensive copy of the request-bound
// ExecutionContext. Missing, invalid, and nil contexts return nil.
func ExecutionContextFromContext(ctx context.Context) *ExecutionContext {
	if ctx == nil {
		return nil
	}
	stored, ok := executioncontextvalue.FromContext(ctx).(*ExecutionContext)
	if !ok || !stored.Valid() {
		return nil
	}
	value := *stored
	return &value
}

// WrapHandler constructs ordinary-human authority immediately after canonical
// authentication. Requests without a typed human Requester, or whose current
// local authority is unavailable, continue without an ExecutionContext.
func (c *HumanExecutionContextConstructor) WrapHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// This wrapper is the canonical producer for the request. Shadow any
		// inherited authority before reconstructing current local authority.
		ctx := executioncontextvalue.Without(req.Context())
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
