package organization

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

const userOrganizationAssignmentColumns = `
	user_id,
	effective_organization_id,
	effective_organization_classification,
	state,
	organization_role,
	assignment_generation,
	mapping_outcome,
	authoritative_evaluated_at,
	source_config_version,
	matched_count,
	evidence_digest,
	pending_transfer_id`

func scanUserOrganizationAssignment(row rowScanner) (*UserOrganizationAssignment, error) {
	var assignment UserOrganizationAssignment
	var classification, state, role, outcome string
	var digest []byte
	var pendingTransferID uuid.NullUUID
	err := row.Scan(
		&assignment.UserID,
		&assignment.EffectiveOrganizationID,
		&classification,
		&state,
		&role,
		&assignment.AssignmentGeneration,
		&outcome,
		&assignment.Evaluation.AuthoritativeEvaluatedAt,
		&assignment.Evaluation.SourceConfigVersion,
		&assignment.Evaluation.MatchedCount,
		&digest,
		&pendingTransferID,
	)
	if err != nil {
		return nil, err
	}
	assignment.EffectiveOrganizationClassification = Classification(classification)
	assignment.State = AssignmentState(state)
	assignment.Role = OrganizationRole(role)
	assignment.MappingOutcome = MappingOutcome(outcome)
	if len(digest) != len(assignment.Evaluation.EvidenceDigest) {
		return nil, fmt.Errorf("%w: invalid evidence digest length", ErrInvariantViolation)
	}
	copy(assignment.Evaluation.EvidenceDigest[:], digest)
	if pendingTransferID.Valid {
		id := pendingTransferID.UUID
		assignment.PendingTransferID = &id
	}
	if err := validateLoadedUserOrganizationAssignment(&assignment); err != nil {
		return nil, err
	}
	return &assignment, nil
}

func effectiveNormalOrganizationID(value UserOrganizationAssignmentValues) any {
	if value.EffectiveOrganizationClassification == ClassificationNormal {
		return value.EffectiveOrganizationID
	}
	return nil
}

func pendingTransferIDValue(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return *id
}

// CreateUserOrganizationAssignment explicitly persists one initial assignment
// for a global User. It performs no lookup, mapping, backfill, or automatic
// Default assignment.
func (s *Store) CreateUserOrganizationAssignment(ctx context.Context, input CreateUserOrganizationAssignmentInput) (*UserOrganizationAssignment, error) {
	if input.UserID == uuid.Nil {
		return nil, fmt.Errorf("%w: User ID is required", ErrInvalidInput)
	}
	if err := validateUserOrganizationAssignmentValues(input.UserOrganizationAssignmentValues); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	assignment, err := scanUserOrganizationAssignment(s.db.QueryRowContext(ctx, `
		INSERT INTO public.user_organization_assignments (
			user_id,
			effective_organization_id,
			effective_organization_classification,
			effective_normal_organization_id,
			state,
			organization_role,
			assignment_generation,
			mapping_outcome,
			authoritative_evaluated_at,
			source_config_version,
			matched_count,
			evidence_digest,
			pending_transfer_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING `+userOrganizationAssignmentColumns,
		input.UserID,
		input.EffectiveOrganizationID,
		input.EffectiveOrganizationClassification,
		effectiveNormalOrganizationID(input.UserOrganizationAssignmentValues),
		input.State,
		input.Role,
		InitialAssignmentGeneration,
		input.MappingOutcome,
		input.Evaluation.AuthoritativeEvaluatedAt,
		input.Evaluation.SourceConfigVersion,
		input.Evaluation.MatchedCount,
		input.Evaluation.EvidenceDigest[:],
		pendingTransferIDValue(input.PendingTransferID),
	))
	if err != nil {
		return nil, mapUserAssignmentWriteError("create UserOrganizationAssignment", err)
	}
	return assignment, nil
}

// FindUserOrganizationAssignment reads the one explicitly persisted assignment
// for a global User. A User without a row remains a valid persisted condition.
func (s *Store) FindUserOrganizationAssignment(ctx context.Context, userID uuid.UUID) (*UserOrganizationAssignment, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("%w: User ID is required", ErrInvalidInput)
	}
	assignment, err := scanUserOrganizationAssignment(s.db.QueryRowContext(ctx, `
		SELECT `+userOrganizationAssignmentColumns+`
		FROM public.user_organization_assignments
		WHERE user_id = $1
	`, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserAssignmentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read UserOrganizationAssignment: %w", err)
	}
	return assignment, nil
}

// GuardedUpdateUserOrganizationAssignment replaces explicitly supplied
// persistence state when ExpectedGeneration is current and advances generation
// by one. It does not resolve assignments or execute a transfer.
func (s *Store) GuardedUpdateUserOrganizationAssignment(ctx context.Context, input GuardedUpdateUserOrganizationAssignmentInput) (*UserOrganizationAssignment, error) {
	if input.UserID == uuid.Nil || input.ExpectedGeneration <= 0 || input.ExpectedGeneration == math.MaxInt64 {
		return nil, fmt.Errorf("%w: User ID and incrementable expected generation are required", ErrInvalidInput)
	}
	if err := validateUserOrganizationAssignmentValues(input.UserOrganizationAssignmentValues); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	assignment, err := scanUserOrganizationAssignment(s.db.QueryRowContext(ctx, `
		UPDATE public.user_organization_assignments
		SET effective_organization_id = $3,
			effective_organization_classification = $4,
			effective_normal_organization_id = $5,
			state = $6,
			organization_role = $7,
			assignment_generation = $2 + 1,
			mapping_outcome = $8,
			authoritative_evaluated_at = $9,
			source_config_version = $10,
			matched_count = $11,
			evidence_digest = $12,
			pending_transfer_id = $13
		WHERE user_id = $1 AND assignment_generation = $2
		RETURNING `+userOrganizationAssignmentColumns,
		input.UserID,
		input.ExpectedGeneration,
		input.EffectiveOrganizationID,
		input.EffectiveOrganizationClassification,
		effectiveNormalOrganizationID(input.UserOrganizationAssignmentValues),
		input.State,
		input.Role,
		input.MappingOutcome,
		input.Evaluation.AuthoritativeEvaluatedAt,
		input.Evaluation.SourceConfigVersion,
		input.Evaluation.MatchedCount,
		input.Evaluation.EvidenceDigest[:],
		pendingTransferIDValue(input.PendingTransferID),
	))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, s.classifyUserAssignmentGuardMiss(ctx, input.UserID, input.ExpectedGeneration)
	}
	if err != nil {
		return nil, mapUserAssignmentWriteError("guarded update UserOrganizationAssignment", err)
	}
	return assignment, nil
}

// RefreshUserOrganizationAssignmentEvidence updates only authoritative mapping
// evidence and keeps generation and effective assignment state unchanged.
func (s *Store) RefreshUserOrganizationAssignmentEvidence(ctx context.Context, input RefreshUserOrganizationAssignmentEvidenceInput) (*UserOrganizationAssignment, error) {
	if input.UserID == uuid.Nil || input.ExpectedGeneration <= 0 {
		return nil, fmt.Errorf("%w: User ID and expected generation are required", ErrInvalidInput)
	}
	if err := validateAssignmentEvaluation(input.Evaluation); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	assignment, err := scanUserOrganizationAssignment(s.db.QueryRowContext(ctx, `
		UPDATE public.user_organization_assignments
		SET authoritative_evaluated_at = $3,
			source_config_version = $4,
			matched_count = $5,
			evidence_digest = $6
		WHERE user_id = $1 AND assignment_generation = $2
		RETURNING `+userOrganizationAssignmentColumns,
		input.UserID,
		input.ExpectedGeneration,
		input.Evaluation.AuthoritativeEvaluatedAt,
		input.Evaluation.SourceConfigVersion,
		input.Evaluation.MatchedCount,
		input.Evaluation.EvidenceDigest[:],
	))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, s.classifyUserAssignmentGuardMiss(ctx, input.UserID, input.ExpectedGeneration)
	}
	if err != nil {
		return nil, mapUserAssignmentWriteError("refresh UserOrganizationAssignment evidence", err)
	}
	return assignment, nil
}

func (s *Store) classifyUserAssignmentGuardMiss(ctx context.Context, userID uuid.UUID, expectedGeneration int64) error {
	var currentGeneration int64
	err := s.db.QueryRowContext(ctx, `
		SELECT assignment_generation
		FROM public.user_organization_assignments
		WHERE user_id = $1
	`, userID).Scan(&currentGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUserAssignmentNotFound
	}
	if err != nil {
		return fmt.Errorf("classify guarded UserOrganizationAssignment write: %w", err)
	}
	if currentGeneration != expectedGeneration {
		return ErrStaleAssignmentGeneration
	}
	return fmt.Errorf("%w: guarded assignment write affected no row", ErrInvariantViolation)
}

func mapUserAssignmentWriteError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var dbErr *pgconn.PgError
	if !errors.As(err, &dbErr) {
		return fmt.Errorf("%s: %w", operation, err)
	}

	var target error
	switch dbErr.Code {
	case "23505":
		if dbErr.ConstraintName == "user_organization_assignments_pkey" &&
			dbErr.SchemaName == "public" && dbErr.TableName == "user_organization_assignments" {
			target = ErrUserAssignmentConflict
		}
	case "23514":
		switch dbErr.ConstraintName {
		case "user_organization_assignments_generation_monotonic",
			"user_organization_assignments_generation_required":
			if dbErr.SchemaName == "public" && dbErr.TableName == "user_organization_assignments" && dbErr.ColumnName == "assignment_generation" {
				target = ErrStaleAssignmentGeneration
			}
		case "user_organization_assignments_evaluated_at_monotonic":
			if dbErr.SchemaName == "public" && dbErr.TableName == "user_organization_assignments" && dbErr.ColumnName == "authoritative_evaluated_at" {
				target = ErrStaleAssignmentEvidence
			}
		default:
			if dbErr.SchemaName == "public" && dbErr.TableName == "user_organization_assignments" {
				target = ErrInvalidInput
			}
		}
	case "23503":
		if dbErr.SchemaName == "public" && dbErr.TableName == "user_organization_assignments" {
			target = ErrInvalidInput
		}
	case "22P02":
		if dbErr.ConstraintName == "" {
			target = ErrInvalidInput
		}
	case "23502":
		if dbErr.ConstraintName == "" && dbErr.SchemaName == "public" && dbErr.TableName == "user_organization_assignments" {
			target = ErrInvalidInput
		}
	}
	if target == nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%w: %s: %w", target, operation, err)
}
