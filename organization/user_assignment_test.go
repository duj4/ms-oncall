package organization

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func validUserOrganizationAssignmentValues() UserOrganizationAssignmentValues {
	return UserOrganizationAssignmentValues{
		EffectiveOrganizationID:             uuid.MustParse("608a7f71-b67f-4a77-a32b-86f76449db21"),
		EffectiveOrganizationClassification: ClassificationNormal,
		State:                               AssignmentStateActive,
		Role:                                OrganizationRoleMember,
		MappingOutcome:                      MappingOutcomeExactlyOne,
		Evaluation: AssignmentEvaluation{
			AuthoritativeEvaluatedAt: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
			SourceConfigVersion:      "mapping-config-v1",
			MatchedCount:             1,
			EvidenceDigest:           sha256.Sum256([]byte("non-secret normalized evidence")),
		},
	}
}

func TestValidateUserOrganizationAssignmentTruthTable(t *testing.T) {
	defaultID := uuid.MustParse(DefaultOrganizationID)
	tests := []struct {
		name   string
		values UserOrganizationAssignmentValues
	}{
		{name: "exactly one member", values: validUserOrganizationAssignmentValues()},
		{name: "exactly one admin", values: func() UserOrganizationAssignmentValues {
			value := validUserOrganizationAssignmentValues()
			value.Role = OrganizationRoleAdmin
			return value
		}()},
		{name: "zero default none", values: func() UserOrganizationAssignmentValues {
			value := validUserOrganizationAssignmentValues()
			value.EffectiveOrganizationID = defaultID
			value.EffectiveOrganizationClassification = ClassificationDefault
			value.Role = OrganizationRoleNone
			value.MappingOutcome = MappingOutcomeZero
			value.Evaluation.MatchedCount = 0
			return value
		}()},
		{name: "multiple default none", values: func() UserOrganizationAssignmentValues {
			value := validUserOrganizationAssignmentValues()
			value.EffectiveOrganizationID = defaultID
			value.EffectiveOrganizationClassification = ClassificationDefault
			value.Role = OrganizationRoleNone
			value.MappingOutcome = MappingOutcomeMultiple
			value.Evaluation.MatchedCount = 2
			return value
		}()},
		{name: "transitioning pending identity", values: func() UserOrganizationAssignmentValues {
			value := validUserOrganizationAssignmentValues()
			value.State = AssignmentStateTransitioning
			id := uuid.MustParse("a64c1ed2-7f69-4a22-a46b-d73701aecfe9")
			value.PendingTransferID = &id
			return value
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateUserOrganizationAssignmentValues(test.values); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateUserOrganizationAssignmentRejectsInvalidValues(t *testing.T) {
	defaultID := uuid.MustParse(DefaultOrganizationID)
	tests := []struct {
		name   string
		mutate func(*UserOrganizationAssignmentValues)
	}{
		{name: "nil effective Organization", mutate: func(v *UserOrganizationAssignmentValues) { v.EffectiveOrganizationID = uuid.Nil }},
		{name: "unknown classification", mutate: func(v *UserOrganizationAssignmentValues) { v.EffectiveOrganizationClassification = "UNKNOWN" }},
		{name: "unknown state", mutate: func(v *UserOrganizationAssignmentValues) { v.State = "UNKNOWN" }},
		{name: "unknown role", mutate: func(v *UserOrganizationAssignmentValues) { v.Role = "UNKNOWN" }},
		{name: "unknown outcome", mutate: func(v *UserOrganizationAssignmentValues) { v.MappingOutcome = "UNKNOWN" }},
		{name: "missing evaluation time", mutate: func(v *UserOrganizationAssignmentValues) { v.Evaluation.AuthoritativeEvaluatedAt = time.Time{} }},
		{name: "blank source version", mutate: func(v *UserOrganizationAssignmentValues) { v.Evaluation.SourceConfigVersion = "" }},
		{name: "untrimmed source version", mutate: func(v *UserOrganizationAssignmentValues) { v.Evaluation.SourceConfigVersion = " version " }},
		{name: "negative matched count", mutate: func(v *UserOrganizationAssignmentValues) { v.Evaluation.MatchedCount = -1 }},
		{name: "missing digest", mutate: func(v *UserOrganizationAssignmentValues) { v.Evaluation.EvidenceDigest = EvidenceDigest{} }},
		{name: "exactly one Default", mutate: func(v *UserOrganizationAssignmentValues) {
			v.EffectiveOrganizationID = defaultID
			v.EffectiveOrganizationClassification = ClassificationDefault
		}},
		{name: "exactly one none", mutate: func(v *UserOrganizationAssignmentValues) { v.Role = OrganizationRoleNone }},
		{name: "exactly one wrong count", mutate: func(v *UserOrganizationAssignmentValues) { v.Evaluation.MatchedCount = 2 }},
		{name: "zero normal", mutate: func(v *UserOrganizationAssignmentValues) {
			v.MappingOutcome = MappingOutcomeZero
			v.Role = OrganizationRoleNone
			v.Evaluation.MatchedCount = 0
		}},
		{name: "zero member", mutate: func(v *UserOrganizationAssignmentValues) {
			v.MappingOutcome = MappingOutcomeZero
			v.EffectiveOrganizationID = defaultID
			v.EffectiveOrganizationClassification = ClassificationDefault
			v.Evaluation.MatchedCount = 0
		}},
		{name: "multiple normal", mutate: func(v *UserOrganizationAssignmentValues) {
			v.MappingOutcome = MappingOutcomeMultiple
			v.Role = OrganizationRoleNone
			v.Evaluation.MatchedCount = 2
		}},
		{name: "multiple one match", mutate: func(v *UserOrganizationAssignmentValues) {
			v.MappingOutcome = MappingOutcomeMultiple
			v.EffectiveOrganizationID = defaultID
			v.EffectiveOrganizationClassification = ClassificationDefault
			v.Role = OrganizationRoleNone
		}},
		{name: "pending identity while active", mutate: func(v *UserOrganizationAssignmentValues) {
			id := uuid.New()
			v.PendingTransferID = &id
		}},
		{name: "nil pending identity", mutate: func(v *UserOrganizationAssignmentValues) {
			v.State = AssignmentStateTransitioning
			id := uuid.Nil
			v.PendingTransferID = &id
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validUserOrganizationAssignmentValues()
			test.mutate(&value)
			if err := validateUserOrganizationAssignmentValues(value); err == nil {
				t.Fatal("invalid UserOrganizationAssignment was accepted")
			}
		})
	}
}

func TestMapUserAssignmentWriteErrorUsesExactIdentity(t *testing.T) {
	conflict := &pgconn.PgError{
		Code:           "23505",
		ConstraintName: "user_organization_assignments_pkey",
		SchemaName:     "public",
		TableName:      "user_organization_assignments",
	}
	if err := mapUserAssignmentWriteError("test", conflict); !errors.Is(err, ErrUserAssignmentConflict) || !errors.Is(err, conflict) {
		t.Fatalf("conflict mapping error = %v", err)
	}

	spoofed := *conflict
	spoofed.SchemaName = "shadow"
	if err := mapUserAssignmentWriteError("test", &spoofed); errors.Is(err, ErrUserAssignmentConflict) {
		t.Fatalf("spoofed constraint identity was classified as conflict: %v", err)
	}

	stale := &pgconn.PgError{
		Code:           "23514",
		ConstraintName: "user_organization_assignments_generation_monotonic",
		SchemaName:     "public",
		TableName:      "user_organization_assignments",
		ColumnName:     "assignment_generation",
	}
	if err := mapUserAssignmentWriteError("test", stale); !errors.Is(err, ErrStaleAssignmentGeneration) || !errors.Is(err, stale) {
		t.Fatalf("stale-generation mapping error = %v", err)
	}
}
