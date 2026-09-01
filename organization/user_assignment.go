package organization

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const InitialAssignmentGeneration int64 = 1

var (
	// ErrUserAssignmentNotFound indicates that no explicit assignment is
	// persisted for the requested global User.
	ErrUserAssignmentNotFound = fmt.Errorf("user Organization assignment not found")
	// ErrUserAssignmentConflict indicates that an assignment already exists for
	// a global User.
	ErrUserAssignmentConflict = fmt.Errorf("user Organization assignment conflict")
	// ErrStaleAssignmentGeneration indicates that a guarded write lost a race
	// with a newer assignment generation.
	ErrStaleAssignmentGeneration = fmt.Errorf("stale user Organization assignment generation")
	// ErrStaleAssignmentEvidence indicates that evaluation evidence is not newer
	// than the evidence already persisted.
	ErrStaleAssignmentEvidence = fmt.Errorf("stale user Organization assignment evidence")
)

// AssignmentState is the bounded durable state of an explicitly persisted
// UserOrganizationAssignment. It does not execute a transfer lifecycle.
type AssignmentState string

const (
	AssignmentStateActive        AssignmentState = "ACTIVE"
	AssignmentStateTransitioning AssignmentState = "TRANSITIONING"
)

// OrganizationRole is the Organization-local role recorded by the assignment.
type OrganizationRole string

const (
	OrganizationRoleMember OrganizationRole = "ORG_MEMBER"
	OrganizationRoleAdmin  OrganizationRole = "ORG_ADMIN"
	OrganizationRoleNone   OrganizationRole = "NONE"
)

// MappingOutcome records the authoritative mapping cardinality that produced
// the effective Organization.
type MappingOutcome string

const (
	MappingOutcomeExactlyOne MappingOutcome = "EXACTLY_ONE"
	MappingOutcomeZero       MappingOutcome = "ZERO"
	MappingOutcomeMultiple   MappingOutcome = "MULTIPLE"
)

// EvidenceDigest is a non-reversible SHA-256 digest. Callers must derive it
// without persisting raw identity-provider claims in this foundation.
type EvidenceDigest [sha256.Size]byte

// AssignmentEvaluation is the bounded authoritative mapping evidence retained
// with an assignment.
type AssignmentEvaluation struct {
	AuthoritativeEvaluatedAt time.Time
	SourceConfigVersion      string
	MatchedCount             int
	EvidenceDigest           EvidenceDigest
}

// UserOrganizationAssignment is the one optional, explicitly persisted
// effective-Organization row for a global User.
type UserOrganizationAssignment struct {
	UserID                              uuid.UUID
	EffectiveOrganizationID             uuid.UUID
	EffectiveOrganizationClassification Classification
	State                               AssignmentState
	Role                                OrganizationRole
	AssignmentGeneration                int64
	MappingOutcome                      MappingOutcome
	Evaluation                          AssignmentEvaluation
	PendingTransferID                   *uuid.UUID
}

// UserOrganizationAssignmentValues are the caller-supplied assignment fields
// used by explicit create and guarded persistence operations.
type UserOrganizationAssignmentValues struct {
	EffectiveOrganizationID             uuid.UUID
	EffectiveOrganizationClassification Classification
	State                               AssignmentState
	Role                                OrganizationRole
	MappingOutcome                      MappingOutcome
	Evaluation                          AssignmentEvaluation
	PendingTransferID                   *uuid.UUID
}

// CreateUserOrganizationAssignmentInput explicitly supplies the global User
// and complete initial assignment state. Generation begins at one.
type CreateUserOrganizationAssignmentInput struct {
	UserID uuid.UUID
	UserOrganizationAssignmentValues
}

// GuardedUpdateUserOrganizationAssignmentInput replaces explicitly supplied
// assignment state only if ExpectedGeneration is current. A successful write
// advances generation by exactly one.
type GuardedUpdateUserOrganizationAssignmentInput struct {
	UserID             uuid.UUID
	ExpectedGeneration int64
	UserOrganizationAssignmentValues
}

// RefreshUserOrganizationAssignmentEvidenceInput changes only evaluation
// evidence while the expected assignment generation remains current.
type RefreshUserOrganizationAssignmentEvidenceInput struct {
	UserID             uuid.UUID
	ExpectedGeneration int64
	Evaluation         AssignmentEvaluation
}

func validateAssignmentState(value AssignmentState) bool {
	return value == AssignmentStateActive || value == AssignmentStateTransitioning
}

func validateOrganizationRole(value OrganizationRole) bool {
	return value == OrganizationRoleMember || value == OrganizationRoleAdmin || value == OrganizationRoleNone
}

func validateMappingOutcome(value MappingOutcome) bool {
	return value == MappingOutcomeExactlyOne || value == MappingOutcomeZero || value == MappingOutcomeMultiple
}

func validateAssignmentEvaluation(value AssignmentEvaluation) error {
	if value.AuthoritativeEvaluatedAt.IsZero() {
		return fmt.Errorf("authoritative evaluation time is required")
	}
	if value.SourceConfigVersion == "" || strings.TrimSpace(value.SourceConfigVersion) != value.SourceConfigVersion {
		return fmt.Errorf("source/config version must be non-empty and trimmed")
	}
	if value.MatchedCount < 0 {
		return fmt.Errorf("matched count cannot be negative")
	}
	if value.EvidenceDigest == (EvidenceDigest{}) {
		return fmt.Errorf("evidence digest is required")
	}
	return nil
}

func validateUserOrganizationAssignmentValues(value UserOrganizationAssignmentValues) error {
	if value.EffectiveOrganizationID == uuid.Nil {
		return fmt.Errorf("effective Organization ID is required")
	}
	if value.EffectiveOrganizationClassification != ClassificationNormal &&
		value.EffectiveOrganizationClassification != ClassificationDefault {
		return fmt.Errorf("unknown effective Organization classification")
	}
	if !validateAssignmentState(value.State) {
		return fmt.Errorf("unknown assignment state")
	}
	if !validateOrganizationRole(value.Role) {
		return fmt.Errorf("unknown Organization role")
	}
	if !validateMappingOutcome(value.MappingOutcome) {
		return fmt.Errorf("unknown mapping outcome")
	}
	if err := validateAssignmentEvaluation(value.Evaluation); err != nil {
		return err
	}
	if value.PendingTransferID != nil {
		if *value.PendingTransferID == uuid.Nil {
			return fmt.Errorf("pending transfer identity cannot be nil UUID")
		}
		if value.State != AssignmentStateTransitioning {
			return fmt.Errorf("pending transfer identity requires TRANSITIONING state")
		}
	}

	defaultID := uuid.MustParse(DefaultOrganizationID)
	switch value.MappingOutcome {
	case MappingOutcomeExactlyOne:
		if value.Evaluation.MatchedCount != 1 ||
			value.EffectiveOrganizationClassification != ClassificationNormal ||
			value.EffectiveOrganizationID == defaultID ||
			(value.Role != OrganizationRoleMember && value.Role != OrganizationRoleAdmin) {
			return fmt.Errorf("EXACTLY_ONE requires one normal Organization match and member or admin role")
		}
	case MappingOutcomeZero:
		if value.Evaluation.MatchedCount != 0 ||
			value.EffectiveOrganizationClassification != ClassificationDefault ||
			value.EffectiveOrganizationID != defaultID || value.Role != OrganizationRoleNone {
			return fmt.Errorf("ZERO requires the distinguished Default Organization and NONE role")
		}
	case MappingOutcomeMultiple:
		if value.Evaluation.MatchedCount <= 1 ||
			value.EffectiveOrganizationClassification != ClassificationDefault ||
			value.EffectiveOrganizationID != defaultID || value.Role != OrganizationRoleNone {
			return fmt.Errorf("MULTIPLE requires the distinguished Default Organization and NONE role")
		}
	}
	return nil
}

func validateLoadedUserOrganizationAssignment(value *UserOrganizationAssignment) error {
	if value == nil || value.UserID == uuid.Nil {
		return fmt.Errorf("%w: missing UserOrganizationAssignment identity", ErrInvariantViolation)
	}
	if value.AssignmentGeneration <= 0 {
		return fmt.Errorf("%w: invalid assignment generation", ErrInvariantViolation)
	}
	values := UserOrganizationAssignmentValues{
		EffectiveOrganizationID:             value.EffectiveOrganizationID,
		EffectiveOrganizationClassification: value.EffectiveOrganizationClassification,
		State:                               value.State,
		Role:                                value.Role,
		MappingOutcome:                      value.MappingOutcome,
		Evaluation:                          value.Evaluation,
		PendingTransferID:                   value.PendingTransferID,
	}
	if err := validateUserOrganizationAssignmentValues(values); err != nil {
		return fmt.Errorf("%w: %v", ErrInvariantViolation, err)
	}
	return nil
}
