package organization

import (
	"crypto/sha256"
	"errors"
	"math"
	"strconv"
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

func TestValidateAssignmentEvaluationSourceConfigVersionWhitespacePolicy(t *testing.T) {
	valid := validUserOrganizationAssignmentValues().Evaluation
	for _, sourceVersion := range []string{
		"mapping-config-v1",
		"配置-v1",
		"mapping\tconfig\nversion",
		"mapping\u3000config",
	} {
		valid.SourceConfigVersion = sourceVersion
		if err := validateAssignmentEvaluation(valid); err != nil {
			t.Fatalf("valid source/config version %q: %v", sourceVersion, err)
		}
	}

	tests := []struct {
		name          string
		sourceVersion string
	}{
		{name: "empty", sourceVersion: ""},
		{name: "ordinary spaces only", sourceVersion: "   "},
		{name: "tab only", sourceVersion: "\t"},
		{name: "newline only", sourceVersion: "\n"},
		{name: "leading tab", sourceVersion: "\tmapping-config-v1"},
		{name: "trailing tab", sourceVersion: "mapping-config-v1\t"},
		{name: "leading newline", sourceVersion: "\nmapping-config-v1"},
		{name: "trailing newline", sourceVersion: "mapping-config-v1\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := valid
			invalid.SourceConfigVersion = test.sourceVersion
			if err := validateAssignmentEvaluation(invalid); err == nil {
				t.Fatalf("invalid source/config version %q was accepted", test.sourceVersion)
			}
		})
	}

	for _, boundaryWhitespace := range sourceConfigVersionBoundaryWhitespace {
		for _, sourceVersion := range []string{
			string(boundaryWhitespace),
			string(boundaryWhitespace) + "mapping-config-v1",
			"mapping-config-v1" + string(boundaryWhitespace),
		} {
			invalid := valid
			invalid.SourceConfigVersion = sourceVersion
			if err := validateAssignmentEvaluation(invalid); err == nil {
				t.Errorf("source/config version with boundary whitespace U+%04X was accepted: %q", boundaryWhitespace, sourceVersion)
			}
		}
	}
}

func TestValidateAssignmentEvaluationSourceConfigVersionRejectsInvalidUTF8(t *testing.T) {
	valid := validUserOrganizationAssignmentValues().Evaluation
	tests := []struct {
		name          string
		sourceVersion string
	}{
		{name: "isolated invalid byte", sourceVersion: string([]byte{0xff})},
		{name: "truncated multi-byte sequence", sourceVersion: string([]byte{0xe2, 0x82})},
		{name: "invalid continuation sequence", sourceVersion: string([]byte{0xe2, 0x28, 0xa1})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := valid
			invalid.SourceConfigVersion = test.sourceVersion
			if err := validateAssignmentEvaluation(invalid); err == nil {
				t.Fatal("invalid UTF-8 source/config version was accepted")
			}
		})
	}
}

func TestValidateAssignmentEvaluationSourceConfigVersionPostgresTextCompatibility(t *testing.T) {
	valid := validUserOrganizationAssignmentValues().Evaluation
	for _, sourceVersion := range []string{
		"ordinary-unicode-配置-v1",
		"embedded\twhitespace\nversion",
		"embedded-\x01-control",
	} {
		valid.SourceConfigVersion = sourceVersion
		if err := validateAssignmentEvaluation(valid); err != nil {
			t.Errorf("PostgreSQL-compatible source/config version %q: %v", sourceVersion, err)
		}
	}

	for _, sourceVersion := range []string{
		"\x00",
		"\x00prefix",
		"suffix\x00",
		"prefix\x00suffix",
		"prefix\x00middle\x00suffix",
		"配置\x00版本",
	} {
		invalid := valid
		invalid.SourceConfigVersion = sourceVersion
		if err := validateAssignmentEvaluation(invalid); err == nil {
			t.Errorf("source/config version containing U+0000 was accepted: %q", sourceVersion)
		}
	}
}

func TestValidateAssignmentEvaluationPostgresTimestamptzRange(t *testing.T) {
	ordinaryUTC := time.Date(2026, time.September, 2, 12, 0, 0, 123456789, time.UTC)
	utcPlusEight := time.FixedZone("UTC+08", 8*60*60)
	tests := []struct {
		name        string
		evaluatedAt time.Time
		wantError   bool
	}{
		{name: "ordinary UTC", evaluatedAt: ordinaryUTC},
		{name: "ordinary same instant non-UTC", evaluatedAt: ordinaryUTC.In(utcPlusEight)},
		{name: "zero", evaluatedAt: time.Time{}, wantError: true},
		{name: "lower endpoint", evaluatedAt: postgresTimestamptzMinimum},
		{name: "inside lower endpoint by nanosecond", evaluatedAt: postgresTimestamptzMinimum.Add(time.Nanosecond)},
		{name: "inside lower endpoint by microsecond", evaluatedAt: postgresTimestamptzMinimum.Add(time.Microsecond)},
		{name: "below lower endpoint by nanosecond", evaluatedAt: postgresTimestamptzMinimum.Add(-time.Nanosecond), wantError: true},
		{name: "clearly valid near upper endpoint", evaluatedAt: postgresTimestamptzEnd.Add(-24 * time.Hour)},
		{name: "last representable microsecond", evaluatedAt: postgresTimestamptzEnd.Add(-time.Microsecond)},
		{name: "sub-microsecond before upper endpoint", evaluatedAt: postgresTimestamptzEnd.Add(-time.Nanosecond)},
		{name: "last representable microsecond same instant non-UTC", evaluatedAt: postgresTimestamptzEnd.Add(-time.Microsecond).In(utcPlusEight)},
		{name: "first non-representable upper instant", evaluatedAt: postgresTimestamptzEnd, wantError: true},
		{name: "beyond upper endpoint", evaluatedAt: postgresTimestamptzEnd.Add(time.Microsecond), wantError: true},
		{name: "reviewer reproduction year 300000", evaluatedAt: time.Date(300000, time.January, 1, 0, 0, 0, 0, time.UTC), wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluation := validUserOrganizationAssignmentValues().Evaluation
			evaluation.AuthoritativeEvaluatedAt = test.evaluatedAt
			err := validateAssignmentEvaluation(evaluation)
			if test.wantError && err == nil {
				t.Fatal("PostgreSQL-incompatible evaluation time was accepted")
			}
			if !test.wantError && err != nil {
				t.Fatalf("PostgreSQL-compatible evaluation time was rejected: %v", err)
			}
		})
	}
}

func TestUserOrganizationAssignmentStoreRejectsInvalidUTF8BeforeSQL(t *testing.T) {
	store := NewStore(nil)
	values := validUserOrganizationAssignmentValues()
	values.Evaluation.SourceConfigVersion = string([]byte{0xff})

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create",
			run: func() error {
				_, err := store.CreateUserOrganizationAssignment(t.Context(), CreateUserOrganizationAssignmentInput{
					UserID:                           uuid.New(),
					UserOrganizationAssignmentValues: values,
				})
				return err
			},
		},
		{
			name: "guarded update",
			run: func() error {
				_, err := store.GuardedUpdateUserOrganizationAssignment(t.Context(), GuardedUpdateUserOrganizationAssignmentInput{
					UserID:                           uuid.New(),
					ExpectedGeneration:               InitialAssignmentGeneration,
					UserOrganizationAssignmentValues: values,
				})
				return err
			},
		},
		{
			name: "evidence refresh",
			run: func() error {
				_, err := store.RefreshUserOrganizationAssignmentEvidence(t.Context(), RefreshUserOrganizationAssignmentEvidenceInput{
					UserID:             uuid.New(),
					ExpectedGeneration: InitialAssignmentGeneration,
					Evaluation:         values.Evaluation,
				})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.run()
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("invalid UTF-8 source/config version error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestUserOrganizationAssignmentStoreRejectsNULBeforeSQL(t *testing.T) {
	store := NewStore(nil)
	values := validUserOrganizationAssignmentValues()
	values.Evaluation.SourceConfigVersion = "prefix\x00配置"

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create",
			run: func() error {
				_, err := store.CreateUserOrganizationAssignment(t.Context(), CreateUserOrganizationAssignmentInput{
					UserID:                           uuid.New(),
					UserOrganizationAssignmentValues: values,
				})
				return err
			},
		},
		{
			name: "guarded update",
			run: func() error {
				_, err := store.GuardedUpdateUserOrganizationAssignment(t.Context(), GuardedUpdateUserOrganizationAssignmentInput{
					UserID:                           uuid.New(),
					ExpectedGeneration:               InitialAssignmentGeneration,
					UserOrganizationAssignmentValues: values,
				})
				return err
			},
		},
		{
			name: "evidence refresh",
			run: func() error {
				_, err := store.RefreshUserOrganizationAssignmentEvidence(t.Context(), RefreshUserOrganizationAssignmentEvidenceInput{
					UserID:             uuid.New(),
					ExpectedGeneration: InitialAssignmentGeneration,
					Evaluation:         values.Evaluation,
				})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.run()
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("U+0000 source/config version error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestUserOrganizationAssignmentStoreRejectsOutOfRangeEvaluationTimeBeforeSQL(t *testing.T) {
	store := NewStore(nil)
	values := validUserOrganizationAssignmentValues()
	values.Evaluation.AuthoritativeEvaluatedAt = time.Date(300000, time.January, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create",
			run: func() error {
				_, err := store.CreateUserOrganizationAssignment(t.Context(), CreateUserOrganizationAssignmentInput{
					UserID:                           uuid.New(),
					UserOrganizationAssignmentValues: values,
				})
				return err
			},
		},
		{
			name: "guarded update",
			run: func() error {
				_, err := store.GuardedUpdateUserOrganizationAssignment(t.Context(), GuardedUpdateUserOrganizationAssignmentInput{
					UserID:                           uuid.New(),
					ExpectedGeneration:               InitialAssignmentGeneration,
					UserOrganizationAssignmentValues: values,
				})
				return err
			},
		},
		{
			name: "evidence refresh",
			run: func() error {
				_, err := store.RefreshUserOrganizationAssignmentEvidence(t.Context(), RefreshUserOrganizationAssignmentEvidenceInput{
					UserID:             uuid.New(),
					ExpectedGeneration: InitialAssignmentGeneration,
					Evaluation:         values.Evaluation,
				})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.run()
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("out-of-range evaluation time error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestValidateAssignmentEvaluationMatchedCountPostgresIntegerRange(t *testing.T) {
	values := validUserOrganizationAssignmentValues()
	values.EffectiveOrganizationID = uuid.MustParse(DefaultOrganizationID)
	values.EffectiveOrganizationClassification = ClassificationDefault
	values.Role = OrganizationRoleNone
	values.MappingOutcome = MappingOutcomeMultiple
	values.Evaluation.MatchedCount = math.MaxInt32
	if err := validateUserOrganizationAssignmentValues(values); err != nil {
		t.Fatalf("PostgreSQL maximum integer matched count was rejected: %v", err)
	}

	if strconv.IntSize < 64 {
		t.Skip("Go int cannot represent a value above PostgreSQL integer on this architecture")
	}
	values.Evaluation.MatchedCount = int(int64(math.MaxInt32) + 1)
	if err := validateUserOrganizationAssignmentValues(values); err == nil {
		t.Fatal("matched count above PostgreSQL integer range was accepted")
	}

	store := NewStore(nil)
	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create",
			run: func() error {
				_, err := store.CreateUserOrganizationAssignment(t.Context(), CreateUserOrganizationAssignmentInput{
					UserID:                           uuid.New(),
					UserOrganizationAssignmentValues: values,
				})
				return err
			},
		},
		{
			name: "guarded update",
			run: func() error {
				_, err := store.GuardedUpdateUserOrganizationAssignment(t.Context(), GuardedUpdateUserOrganizationAssignmentInput{
					UserID:                           uuid.New(),
					ExpectedGeneration:               InitialAssignmentGeneration,
					UserOrganizationAssignmentValues: values,
				})
				return err
			},
		},
		{
			name: "evidence refresh",
			run: func() error {
				_, err := store.RefreshUserOrganizationAssignmentEvidence(t.Context(), RefreshUserOrganizationAssignmentEvidenceInput{
					UserID:             uuid.New(),
					ExpectedGeneration: InitialAssignmentGeneration,
					Evaluation:         values.Evaluation,
				})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.run()
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("matched count above PostgreSQL integer range error = %v, want ErrInvalidInput", err)
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
