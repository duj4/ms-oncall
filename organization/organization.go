package organization

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	coretimezone "github.com/target/goalert/timezone"
)

const (
	// DefaultOrganizationID is the deterministic durable identity inserted by
	// the canonical Organization persistence migration.
	DefaultOrganizationID = "296e2656-7221-53fe-bd0a-832d24ccfd03"

	// DefaultOrganizationCanonicalName is the immutable canonical identity of
	// the distinguished Default Organization.
	DefaultOrganizationCanonicalName = "ms-oncall.default"
)

var (
	// ErrNotFound indicates that the requested Organization does not exist.
	ErrNotFound = errors.New("organization not found")
	// ErrConflict indicates a globally unique Organization identity or mapping
	// key is already in use.
	ErrConflict = errors.New("organization conflict")
	// ErrInvalidInput indicates malformed or unsupported caller input.
	ErrInvalidInput = errors.New("invalid organization input")
	// ErrInvalidLifecycleTransition indicates a transition outside the explicit
	// lifecycle policy.
	ErrInvalidLifecycleTransition = errors.New("invalid organization lifecycle transition")
	// ErrInvariantViolation indicates contradictory durable Organization state.
	ErrInvariantViolation = errors.New("organization persistence invariant violation")
)

// Classification identifies whether an Organization is operationally normal
// or the distinguished non-operational Default.
type Classification string

const (
	ClassificationNormal  Classification = "NORMAL"
	ClassificationDefault Classification = "DEFAULT"
)

// Lifecycle is the durable lifecycle of an Organization identity.
type Lifecycle string

const (
	LifecycleActive    Lifecycle = "ACTIVE"
	LifecycleSuspended Lifecycle = "SUSPENDED"
	LifecycleRetired   Lifecycle = "RETIRED"
)

// Organization is the stable base identity persisted for both normal and
// Default Organizations.
type Organization struct {
	ID             uuid.UUID
	Classification Classification
	DisplayName    string
	CanonicalName  string
	Lifecycle      Lifecycle
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// NormalOrganization is the constrained operational subtype of Organization.
type NormalOrganization struct {
	Organization
	CorporateMappingKey string
	TimeZone            string
}

// CreateNormalOrganizationInput contains the only caller-controlled fields
// accepted when transactionally creating a normal Organization.
type CreateNormalOrganizationInput struct {
	DisplayName         string
	CanonicalName       string
	CorporateMappingKey string
	TimeZone            string
}

func validateClassification(value Classification) error {
	switch value {
	case ClassificationNormal, ClassificationDefault:
		return nil
	default:
		return fmt.Errorf("%w: unknown classification", ErrInvariantViolation)
	}
}

func validateLifecycle(value Lifecycle) error {
	switch value {
	case LifecycleActive, LifecycleSuspended, LifecycleRetired:
		return nil
	default:
		return fmt.Errorf("%w: unknown lifecycle", ErrInvariantViolation)
	}
}

func validateMutableLifecycleTarget(value Lifecycle) error {
	switch value {
	case LifecycleActive, LifecycleSuspended, LifecycleRetired:
		return nil
	default:
		return fmt.Errorf("%w: unknown lifecycle", ErrInvalidInput)
	}
}

func lifecycleTransitionAllowed(from, to Lifecycle) bool {
	if from == to {
		return true
	}
	switch from {
	case LifecycleActive:
		return to == LifecycleSuspended || to == LifecycleRetired
	case LifecycleSuspended:
		return to == LifecycleActive || to == LifecycleRetired
	case LifecycleRetired:
		return false
	default:
		return false
	}
}

func validateCreateInput(input CreateNormalOrganizationInput) (CreateNormalOrganizationInput, error) {
	if strings.TrimSpace(input.DisplayName) == "" {
		return input, fmt.Errorf("%w: display name is required", ErrInvalidInput)
	}
	if strings.TrimSpace(input.CanonicalName) == "" || strings.TrimSpace(input.CanonicalName) != input.CanonicalName {
		return input, fmt.Errorf("%w: canonical name must be non-empty and trimmed", ErrInvalidInput)
	}
	if strings.TrimSpace(input.CorporateMappingKey) == "" || strings.TrimSpace(input.CorporateMappingKey) != input.CorporateMappingKey {
		return input, fmt.Errorf("%w: corporate mapping key must be non-empty and trimmed", ErrInvalidInput)
	}
	zone, err := canonicalTimeZone(input.TimeZone)
	if err != nil {
		return input, err
	}
	input.TimeZone = zone
	return input, nil
}

func canonicalTimeZone(value string) (string, error) {
	if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value {
		return "", fmt.Errorf("%w: IANA time zone must be non-empty and trimmed", ErrInvalidInput)
	}
	zone := coretimezone.CanonicalZone(value)
	if zone == "" {
		return "", fmt.Errorf("%w: unknown IANA time zone", ErrInvalidInput)
	}
	return zone, nil
}

func validateLoadedOrganization(org *Organization) error {
	if org == nil || org.ID == uuid.Nil {
		return fmt.Errorf("%w: missing stable identity", ErrInvariantViolation)
	}
	if err := validateClassification(org.Classification); err != nil {
		return err
	}
	if strings.TrimSpace(org.DisplayName) == "" || strings.TrimSpace(org.CanonicalName) == "" || strings.TrimSpace(org.CanonicalName) != org.CanonicalName {
		return fmt.Errorf("%w: invalid persisted identity", ErrInvariantViolation)
	}
	if err := validateLifecycle(org.Lifecycle); err != nil {
		return err
	}
	if org.CreatedAt.IsZero() || org.UpdatedAt.IsZero() || org.UpdatedAt.Before(org.CreatedAt) {
		return fmt.Errorf("%w: invalid audit timestamps", ErrInvariantViolation)
	}
	return nil
}
