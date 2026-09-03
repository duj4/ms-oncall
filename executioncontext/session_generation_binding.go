package executioncontext

import (
	"errors"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

var errInvalidSessionGenerationBinding = errors.New("invalid SessionGenerationBinding")

// SessionGenerationCurrentState is caller-supplied state used only for a pure
// comparison with captured session-generation evidence. It does not establish
// that the supplied state is authentic or authoritative.
type SessionGenerationCurrentState struct {
	UserID                  uuid.UUID
	AssignmentState         organization.AssignmentState
	AssignmentGeneration    int64
	HumanSecurityGeneration int64
}

// SessionGenerationBinding is immutable evidence binding stable session and
// global User identities to captured assignment and human-security
// generations. Its fields are private, its zero value is invalid, and no public
// construction or restoration path is provided.
//
// A valid or current binding does not authenticate a request, prove that a
// session exists or remains unrevoked, or grant any authorization.
type SessionGenerationBinding struct {
	valid                   bool
	sessionID               uuid.UUID
	userID                  uuid.UUID
	assignmentGeneration    int64
	humanSecurityGeneration int64
}

// Valid reports whether the binding was completely validated by the private
// trusted construction seam. Nil and zero values are invalid.
func (b *SessionGenerationBinding) Valid() bool { return b != nil && b.valid }

// SessionID returns the captured stable session identity. It does not prove
// that a corresponding session exists or remains unrevoked.
func (b *SessionGenerationBinding) SessionID() (uuid.UUID, bool) {
	if !b.Valid() {
		return uuid.Nil, false
	}
	return b.sessionID, true
}

// UserID returns the captured stable global User identity.
func (b *SessionGenerationBinding) UserID() (uuid.UUID, bool) {
	if !b.Valid() {
		return uuid.Nil, false
	}
	return b.userID, true
}

// AssignmentGeneration returns the captured positive assignment generation.
func (b *SessionGenerationBinding) AssignmentGeneration() (int64, bool) {
	if !b.Valid() {
		return 0, false
	}
	return b.assignmentGeneration, true
}

// HumanSecurityGeneration returns the captured positive human-security
// generation. This contract defines no persistence or lifecycle for it.
func (b *SessionGenerationBinding) HumanSecurityGeneration() (int64, bool) {
	if !b.Valid() {
		return 0, false
	}
	return b.humanSecurityGeneration, true
}

// CurrentAgainst reports only whether the captured generation-binding evidence
// exactly matches the explicitly supplied current state. It performs no lookup
// and does not prove the supplied state is authentic. A true result neither
// authenticates nor authorizes.
func (b *SessionGenerationBinding) CurrentAgainst(current SessionGenerationCurrentState) bool {
	return b.Valid() &&
		current.UserID != uuid.Nil &&
		current.UserID == b.userID &&
		current.AssignmentState == organization.AssignmentStateActive &&
		current.AssignmentGeneration > 0 &&
		current.AssignmentGeneration == b.assignmentGeneration &&
		current.HumanSecurityGeneration > 0 &&
		current.HumanSecurityGeneration == b.humanSecurityGeneration
}

// newSessionGenerationBinding is the package-private validation seam used by
// contract tests only. It returns the invalid zero value on every failure and
// deliberately has no runtime producer.
func newSessionGenerationBinding(
	sessionID uuid.UUID,
	userID uuid.UUID,
	assignmentGeneration int64,
	humanSecurityGeneration int64,
) (SessionGenerationBinding, error) {
	var zero SessionGenerationBinding

	if sessionID == uuid.Nil || userID == uuid.Nil || assignmentGeneration <= 0 || humanSecurityGeneration <= 0 {
		return zero, errInvalidSessionGenerationBinding
	}

	return SessionGenerationBinding{
		valid:                   true,
		sessionID:               sessionID,
		userID:                  userID,
		assignmentGeneration:    assignmentGeneration,
		humanSecurityGeneration: humanSecurityGeneration,
	}, nil
}
