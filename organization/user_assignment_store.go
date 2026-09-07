package organization

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

const userOrganizationAssignmentColumns = `
	user_id,
	effective_organization_id,
	effective_organization_classification,
	organization_role,
	mapping_outcome,
	authoritative_evaluated_at,
	source_config_version,
	matched_count`

func scanUserOrganizationAssignment(row rowScanner) (*UserOrganizationAssignment, error) {
	var assignment UserOrganizationAssignment
	var classification, role, outcome string
	err := row.Scan(
		&assignment.UserID,
		&assignment.EffectiveOrganizationID,
		&classification,
		&role,
		&outcome,
		&assignment.Evaluation.AuthoritativeEvaluatedAt,
		&assignment.Evaluation.SourceConfigVersion,
		&assignment.Evaluation.MatchedCount,
	)
	if err != nil {
		return nil, err
	}
	assignment.EffectiveOrganizationClassification = Classification(classification)
	assignment.Role = OrganizationRole(role)
	assignment.MappingOutcome = MappingOutcome(outcome)
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
			organization_role,
			mapping_outcome,
			authoritative_evaluated_at,
			source_config_version,
			matched_count
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING `+userOrganizationAssignmentColumns,
		input.UserID,
		input.EffectiveOrganizationID,
		input.EffectiveOrganizationClassification,
		effectiveNormalOrganizationID(input.UserOrganizationAssignmentValues),
		input.Role,
		input.MappingOutcome,
		input.Evaluation.AuthoritativeEvaluatedAt,
		input.Evaluation.SourceConfigVersion,
		input.Evaluation.MatchedCount,
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
		if dbErr.SchemaName == "public" && dbErr.TableName == "user_organization_assignments" {
			target = ErrInvalidInput
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
