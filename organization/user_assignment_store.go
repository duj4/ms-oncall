package organization

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/target/goalert/permission"
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

// CurrentUserOrganization is the bounded read projection used when composing
// one request's current ordinary Organization context. It is not persisted and
// deliberately excludes mapping provenance and Organization presentation
// fields.
type CurrentUserOrganization struct {
	UserID         uuid.UUID
	UserRole       permission.Role
	OrganizationID uuid.UUID
	Role           OrganizationRole
}

const findCurrentUserOrganizationQuery = `
	SELECT
		u.id,
		u.role,
		a.effective_organization_id,
		a.organization_role
	FROM public.users AS u
	INNER JOIN public.user_organization_assignments AS a
		ON a.user_id = u.id
	INNER JOIN public.organizations AS o
		ON o.id = a.effective_organization_id
		AND o.classification = a.effective_organization_classification
	INNER JOIN public.normal_organizations AS n
		ON n.organization_id = o.id
		AND n.organization_classification = o.classification
		AND n.organization_id = a.effective_normal_organization_id
	WHERE u.id = $1
		AND u.role IN ('user', 'admin')
		AND a.mapping_outcome = 'EXACTLY_ONE'
		AND a.matched_count = 1
		AND a.effective_organization_classification = 'NORMAL'
		AND a.effective_organization_id <> $2
		AND a.effective_normal_organization_id = a.effective_organization_id
		AND a.organization_role IN ('ORG_MEMBER', 'ORG_ADMIN')
		AND o.classification = 'NORMAL'
		AND n.organization_classification = 'NORMAL'
`

// FindCurrentUserOrganization observes the current User, assignment, base
// Organization, and NormalOrganization relationship in one SQL statement. A
// non-operational or contradictory combination is indistinguishable from not
// found so callers cannot repair it into authority.
func (s *Store) FindCurrentUserOrganization(ctx context.Context, userID uuid.UUID) (*CurrentUserOrganization, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("%w: User ID is required", ErrInvalidInput)
	}

	var value CurrentUserOrganization
	var userRole, organizationRole string
	err := s.db.QueryRowContext(ctx, findCurrentUserOrganizationQuery, userID, DefaultOrganizationID).Scan(
		&value.UserID,
		&userRole,
		&value.OrganizationID,
		&organizationRole,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read current User Organization: %w", err)
	}

	value.UserRole = permission.Role(userRole)
	value.Role = OrganizationRole(organizationRole)
	if value.UserID != userID || value.OrganizationID == uuid.Nil || value.OrganizationID.String() == DefaultOrganizationID ||
		(value.UserRole != permission.RoleUser && value.UserRole != permission.RoleAdmin) ||
		(value.Role != OrganizationRoleMember && value.Role != OrganizationRoleAdmin) {
		return nil, fmt.Errorf("%w: invalid current User Organization projection", ErrInvariantViolation)
	}
	return &value, nil
}

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
