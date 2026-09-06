package executioncontext

import (
	"context"
	"net/http"

	"github.com/target/goalert/auth"
)

type currentHumanAuthorityContextKey struct{}

// WithCurrentHumanAuthority returns a context carrying a defensive copy of a
// valid operation-local CurrentHumanAuthority. Invalid authorities are not
// installed.
func WithCurrentHumanAuthority(ctx context.Context, authority CurrentHumanAuthority) context.Context {
	if ctx == nil || !authority.Valid() {
		return ctx
	}
	return context.WithValue(ctx, currentHumanAuthorityContextKey{}, authority)
}

// CurrentHumanAuthorityFromContext returns a defensive copy of the valid
// operation-local CurrentHumanAuthority in ctx. Missing, invalid, and nil
// contexts return nil.
func CurrentHumanAuthorityFromContext(ctx context.Context) *CurrentHumanAuthority {
	if ctx == nil {
		return nil
	}
	authority, ok := ctx.Value(currentHumanAuthorityContextKey{}).(CurrentHumanAuthority)
	if !ok || !authority.Valid() {
		return nil
	}
	return &authority
}

// WrapHandler composes current ordinary-human authority immediately after
// canonical authentication. Requests without a typed human Requester and
// requests whose current local authority is unavailable continue unchanged and
// receive no trusted ordinary-human authority. This foundation does not make a
// business-authorization decision or implement the Complete Operation Guard.
func (c *CurrentHumanAuthorityConstructor) WrapHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// This wrapper is the canonical producer for the request. Shadow any
		// earlier operation-local value before deciding whether a fresh one can
		// be constructed.
		ctx := context.WithValue(req.Context(), currentHumanAuthorityContextKey{}, CurrentHumanAuthority{})
		req = req.WithContext(ctx)

		if auth.RequesterFromContext(ctx) == nil {
			next.ServeHTTP(w, req)
			return
		}

		authority, err := c.Construct(ctx)
		if err != nil || !authority.Valid() {
			next.ServeHTTP(w, req)
			return
		}

		next.ServeHTTP(w, req.WithContext(WithCurrentHumanAuthority(ctx, authority)))
	})
}
