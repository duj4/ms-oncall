package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErrInvalidRequester indicates that an authenticated-human Requester could
// not be constructed from canonical non-zero User and Session identities.
var ErrInvalidRequester = errors.New("invalid authenticated-human Requester")

// Requester identifies the global human User and local Session that entered a
// request through canonical authentication. It carries no Organization,
// privilege, assignment, or authorization state. Its zero value is invalid.
type Requester struct {
	userID    uuid.UUID
	sessionID uuid.UUID
}

// NewRequester constructs an identity-only authenticated-human Requester.
// Both inputs must use the canonical lowercase UUID representation.
func NewRequester(userID, sessionID string) (Requester, error) {
	var zero Requester
	parsedUserID, ok := parseCanonicalRequesterUUID(userID)
	if !ok {
		return zero, fmt.Errorf("%w: invalid User identity", ErrInvalidRequester)
	}
	parsedSessionID, ok := parseCanonicalRequesterUUID(sessionID)
	if !ok {
		return zero, fmt.Errorf("%w: invalid Session identity", ErrInvalidRequester)
	}
	return Requester{userID: parsedUserID, sessionID: parsedSessionID}, nil
}

// Valid reports whether the Requester contains both required identities.
func (r *Requester) Valid() bool {
	return r != nil && r.userID != uuid.Nil && r.sessionID != uuid.Nil
}

// UserID returns the authenticated global User identity. Nil and invalid
// Requesters return uuid.Nil.
func (r *Requester) UserID() uuid.UUID {
	if !r.Valid() {
		return uuid.Nil
	}
	return r.userID
}

// SessionID returns the authenticated local Session identity. Nil and invalid
// Requesters return uuid.Nil.
func (r *Requester) SessionID() uuid.UUID {
	if !r.Valid() {
		return uuid.Nil
	}
	return r.sessionID
}

type requesterContextKey struct{}

// WithRequester returns a context carrying a defensive copy of a valid
// authenticated-human Requester. Invalid Requesters are not installed.
func WithRequester(ctx context.Context, requester Requester) context.Context {
	if ctx == nil || !requester.Valid() {
		return ctx
	}
	return context.WithValue(ctx, requesterContextKey{}, requester)
}

// withoutRequester returns a context that shadows any inherited Requester.
// Canonical HTTP authentication uses it before selecting an authentication
// branch so only successful authentication for the current request can install
// an authenticated-human Requester.
func withoutRequester(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, requesterContextKey{}, Requester{})
}

// RequesterFromContext returns a defensive copy of the authenticated-human
// Requester in ctx. Missing, invalid, and nil contexts return nil.
func RequesterFromContext(ctx context.Context) *Requester {
	if ctx == nil {
		return nil
	}
	requester, ok := ctx.Value(requesterContextKey{}).(Requester)
	if !ok || !requester.Valid() {
		return nil
	}
	return &requester
}

func parseCanonicalRequesterUUID(value string) (uuid.UUID, bool) {
	id, err := uuid.Parse(value)
	return id, err == nil && id != uuid.Nil && id.String() == value
}
