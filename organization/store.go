package organization

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/target/goalert/util/sqlutil"
)

// Store provides the minimal internal Organization persistence surface. It has
// no generic base-Organization creation or hard-delete operation.
type Store struct {
	db *sql.DB
}

// NewStore creates an internal Organization persistence store.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

type rowScanner interface {
	Scan(dest ...any) error
}

type rowQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

const organizationColumns = `id, classification, display_name, canonical_name, lifecycle, created_at, updated_at`

func scanOrganization(row rowScanner) (*Organization, error) {
	var org Organization
	var classification, lifecycle string
	err := row.Scan(
		&org.ID,
		&classification,
		&org.DisplayName,
		&org.CanonicalName,
		&lifecycle,
		&org.CreatedAt,
		&org.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	org.Classification = Classification(classification)
	org.Lifecycle = Lifecycle(lifecycle)
	if err := validateLoadedOrganization(&org); err != nil {
		return nil, err
	}
	return &org, nil
}

func scanNormalOrganization(row rowScanner) (*NormalOrganization, error) {
	var normal NormalOrganization
	var classification, lifecycle string
	err := row.Scan(
		&normal.ID,
		&classification,
		&normal.DisplayName,
		&normal.CanonicalName,
		&lifecycle,
		&normal.CreatedAt,
		&normal.UpdatedAt,
		&normal.CorporateMappingKey,
		&normal.TimeZone,
	)
	if err != nil {
		return nil, err
	}
	normal.Classification = Classification(classification)
	normal.Lifecycle = Lifecycle(lifecycle)
	if err := validateLoadedOrganization(&normal.Organization); err != nil {
		return nil, err
	}
	if normal.Classification != ClassificationNormal {
		return nil, fmt.Errorf("%w: subtype base is not NORMAL", ErrInvariantViolation)
	}
	if strings.TrimSpace(normal.CorporateMappingKey) == "" || strings.TrimSpace(normal.CorporateMappingKey) != normal.CorporateMappingKey {
		return nil, fmt.Errorf("%w: invalid corporate mapping key", ErrInvariantViolation)
	}
	zone, err := canonicalTimeZone(normal.TimeZone)
	if err != nil || zone != normal.TimeZone {
		return nil, fmt.Errorf("%w: invalid canonical IANA time zone", ErrInvariantViolation)
	}
	return &normal, nil
}

func findOrganization(ctx context.Context, db rowQueryer, id uuid.UUID, lock bool) (*Organization, error) {
	query := `SELECT ` + organizationColumns + ` FROM organizations WHERE id = $1`
	if lock {
		query += ` FOR UPDATE`
	}
	org, err := scanOrganization(db.QueryRowContext(ctx, query, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read Organization: %w", err)
	}
	return org, nil
}

func findNormalOrganization(ctx context.Context, db rowQueryer, predicate string, value any) (*NormalOrganization, error) {
	query := `
		SELECT o.id, o.classification, o.display_name, o.canonical_name,
			o.lifecycle, o.created_at, o.updated_at,
			n.corporate_mapping_key, n.iana_time_zone
		FROM normal_organizations n
		JOIN organizations o
			ON o.id = n.organization_id
			AND o.classification = n.organization_classification
		WHERE ` + predicate
	normal, err := scanNormalOrganization(db.QueryRowContext(ctx, query, value))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read Normal Organization: %w", err)
	}
	return normal, nil
}

// CreateNormal creates the base and NORMAL subtype in one transaction. The
// initial lifecycle is always ACTIVE and the stable UUID is generated here.
func (s *Store) CreateNormal(ctx context.Context, input CreateNormalOrganizationInput) (*NormalOrganization, error) {
	input, err := validateCreateInput(input)
	if err != nil {
		return nil, err
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("generate Organization identity: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin Organization create: %w", err)
	}
	defer sqlutil.Rollback(ctx, "organization: create normal", tx)

	_, err = tx.ExecContext(ctx, `
		INSERT INTO organizations (
			id, classification, display_name, canonical_name, lifecycle
		) VALUES ($1, 'NORMAL', $2, $3, 'ACTIVE')
	`, id, input.DisplayName, input.CanonicalName)
	if err != nil {
		return nil, mapWriteError("create Organization base", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO normal_organizations (
			organization_id, organization_classification,
			corporate_mapping_key, iana_time_zone
		) VALUES ($1, 'NORMAL', $2, $3)
	`, id, input.CorporateMappingKey, input.TimeZone)
	if err != nil {
		return nil, mapWriteError("create Normal Organization subtype", err)
	}
	normal, err := findNormalOrganization(ctx, tx, "n.organization_id = $1", id)
	if err != nil {
		return nil, fmt.Errorf("verify created Normal Organization: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, mapWriteError("commit Normal Organization create", err)
	}
	return normal, nil
}

// FindByID reads a base Organization by stable UUID.
func (s *Store) FindByID(ctx context.Context, id uuid.UUID) (*Organization, error) {
	if id == uuid.Nil {
		return nil, fmt.Errorf("%w: Organization ID is required", ErrInvalidInput)
	}
	return findOrganization(ctx, s.db, id, false)
}

// FindNormalByID reads a constrained Normal Organization by stable UUID.
func (s *Store) FindNormalByID(ctx context.Context, id uuid.UUID) (*NormalOrganization, error) {
	if id == uuid.Nil {
		return nil, fmt.Errorf("%w: Organization ID is required", ErrInvalidInput)
	}
	normal, err := findNormalOrganization(ctx, s.db, "n.organization_id = $1", id)
	if !errors.Is(err, ErrNotFound) {
		return normal, err
	}
	base, baseErr := findOrganization(ctx, s.db, id, false)
	switch {
	case errors.Is(baseErr, ErrNotFound):
		return nil, ErrNotFound
	case baseErr != nil:
		return nil, baseErr
	case base.Classification == ClassificationDefault:
		return nil, ErrNotFound
	default:
		return nil, fmt.Errorf("%w: NORMAL base has no subtype", ErrInvariantViolation)
	}
}

// FindNormalByCorporateMappingKey resolves the globally unique immutable
// corporate mapping key.
func (s *Store) FindNormalByCorporateMappingKey(ctx context.Context, key string) (*NormalOrganization, error) {
	if strings.TrimSpace(key) == "" || strings.TrimSpace(key) != key {
		return nil, fmt.Errorf("%w: corporate mapping key must be non-empty and trimmed", ErrInvalidInput)
	}
	return findNormalOrganization(ctx, s.db, "n.corporate_mapping_key = $1", key)
}

// FindDefault returns the one migration-owned distinguished Default
// Organization. Missing or contradictory state is an invariant violation.
func (s *Store) FindDefault(ctx context.Context) (*Organization, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+organizationColumns+`
		FROM organizations
		WHERE classification = 'DEFAULT'
		ORDER BY id
		LIMIT 2
	`)
	if err != nil {
		return nil, fmt.Errorf("read distinguished Default Organization: %w", err)
	}
	defer rows.Close()

	var found []*Organization
	for rows.Next() {
		org, err := scanOrganization(rows)
		if err != nil {
			return nil, fmt.Errorf("scan distinguished Default Organization: %w", err)
		}
		found = append(found, org)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate distinguished Default Organization: %w", err)
	}
	if len(found) != 1 || found[0].ID.String() != DefaultOrganizationID || found[0].CanonicalName != DefaultOrganizationCanonicalName {
		return nil, fmt.Errorf("%w: distinguished Default Organization identity is missing or contradictory", ErrInvariantViolation)
	}
	return found[0], nil
}

// UpdateDisplayName changes only a normal Organization's display identity.
func (s *Store) UpdateDisplayName(ctx context.Context, id uuid.UUID, displayName string) (*Organization, error) {
	if id == uuid.Nil || strings.TrimSpace(displayName) == "" {
		return nil, fmt.Errorf("%w: Organization ID and display name are required", ErrInvalidInput)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin Organization display update: %w", err)
	}
	defer sqlutil.Rollback(ctx, "organization: update display", tx)

	org, err := scanOrganization(tx.QueryRowContext(ctx, `
		UPDATE organizations
		SET display_name = $2
		WHERE id = $1 AND classification = 'NORMAL'
		RETURNING `+organizationColumns,
		id, displayName,
	))
	if errors.Is(err, sql.ErrNoRows) {
		base, baseErr := findOrganization(ctx, tx, id, true)
		if baseErr != nil {
			return nil, baseErr
		}
		if base.Classification != ClassificationNormal {
			return nil, fmt.Errorf("%w: Default Organization is not mutable through the normal store", ErrInvalidInput)
		}
		return nil, fmt.Errorf("%w: failed to update normal Organization", ErrInvariantViolation)
	}
	if err != nil {
		return nil, mapWriteError("update Organization display name", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, mapWriteError("commit Organization display update", err)
	}
	return org, nil
}

// UpdateTimeZone canonicalizes and changes only a Normal Organization's IANA
// time-zone name. The subtype trigger also advances the base audit timestamp.
func (s *Store) UpdateTimeZone(ctx context.Context, id uuid.UUID, timeZone string) (*NormalOrganization, error) {
	if id == uuid.Nil {
		return nil, fmt.Errorf("%w: Organization ID is required", ErrInvalidInput)
	}
	zone, err := canonicalTimeZone(timeZone)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin Normal Organization time-zone update: %w", err)
	}
	defer sqlutil.Rollback(ctx, "organization: update time zone", tx)

	result, err := tx.ExecContext(ctx, `
		UPDATE normal_organizations
		SET iana_time_zone = $2
		WHERE organization_id = $1
	`, id, zone)
	if err != nil {
		return nil, mapWriteError("update Normal Organization time zone", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("inspect Normal Organization time-zone update: %w", err)
	}
	if rows != 1 {
		base, baseErr := findOrganization(ctx, tx, id, true)
		switch {
		case errors.Is(baseErr, ErrNotFound):
			return nil, ErrNotFound
		case baseErr != nil:
			return nil, baseErr
		case base.Classification == ClassificationDefault:
			return nil, fmt.Errorf("%w: Default Organization has no normal subtype", ErrInvalidInput)
		default:
			return nil, fmt.Errorf("%w: NORMAL base has no subtype", ErrInvariantViolation)
		}
	}
	normal, err := findNormalOrganization(ctx, tx, "n.organization_id = $1", id)
	if err != nil {
		return nil, fmt.Errorf("verify Normal Organization time-zone update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, mapWriteError("commit Normal Organization time-zone update", err)
	}
	return normal, nil
}

// TransitionLifecycle applies the explicit lifecycle policy to a normal
// Organization. A same-state request is a successful no-op and leaves the
// audit timestamp unchanged. RETIRED is terminal.
func (s *Store) TransitionLifecycle(ctx context.Context, id uuid.UUID, target Lifecycle) (*Organization, error) {
	if id == uuid.Nil {
		return nil, fmt.Errorf("%w: Organization ID is required", ErrInvalidInput)
	}
	if err := validateMutableLifecycleTarget(target); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin Organization lifecycle transition: %w", err)
	}
	defer sqlutil.Rollback(ctx, "organization: lifecycle transition", tx)

	org, err := findOrganization(ctx, tx, id, true)
	if err != nil {
		return nil, err
	}
	if org.Classification != ClassificationNormal {
		return nil, fmt.Errorf("%w: Default Organization lifecycle is not mutable through the normal store", ErrInvalidInput)
	}
	if !lifecycleTransitionAllowed(org.Lifecycle, target) {
		return nil, fmt.Errorf("%w: %s to %s", ErrInvalidLifecycleTransition, org.Lifecycle, target)
	}
	if org.Lifecycle == target {
		if err := tx.Commit(); err != nil {
			return nil, mapWriteError("commit same-state lifecycle transition", err)
		}
		return org, nil
	}

	updated, err := scanOrganization(tx.QueryRowContext(ctx, `
		UPDATE organizations
		SET lifecycle = $2
		WHERE id = $1 AND classification = 'NORMAL' AND lifecycle = $3
		RETURNING `+organizationColumns,
		id, target, org.Lifecycle,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: lifecycle changed concurrently", ErrInvariantViolation)
	}
	if err != nil {
		return nil, mapWriteError("transition Organization lifecycle", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, mapWriteError("commit Organization lifecycle transition", err)
	}
	return updated, nil
}

func mapWriteError(operation string, err error) error {
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
		switch dbErr.ConstraintName {
		case "organizations_pkey", "organizations_canonical_name_key", "organizations_id_classification_key", "organizations_single_default_idx":
			if dbErr.SchemaName == "public" && dbErr.TableName == "organizations" {
				target = ErrConflict
			}
		case "normal_organizations_pkey", "normal_organizations_corporate_mapping_key_key":
			if dbErr.SchemaName == "public" && dbErr.TableName == "normal_organizations" {
				target = ErrConflict
			}
		}
	case "23514":
		switch dbErr.ConstraintName {
		case "organizations_lifecycle_transition":
			if dbErr.SchemaName == "public" && dbErr.TableName == "organizations" && dbErr.ColumnName == "lifecycle" {
				target = ErrInvalidLifecycleTransition
			}
		case "organizations_display_name_not_blank",
			"organizations_canonical_name_not_blank",
			"organizations_audit_timestamp_order",
			"organizations_default_delete_forbidden",
			"organizations_id_immutable",
			"organizations_classification_immutable",
			"organizations_canonical_name_immutable",
			"organizations_created_at_immutable",
			"organizations_default_lifecycle_immutable":
			if dbErr.SchemaName == "public" && dbErr.TableName == "organizations" {
				target = ErrInvariantViolation
			}
		case "normal_organizations_classification_normal",
			"normal_organizations_corporate_mapping_key_not_blank",
			"normal_organizations_iana_time_zone_not_blank",
			"normal_organizations_organization_id_immutable",
			"normal_organizations_classification_immutable",
			"normal_organizations_corporate_mapping_key_immutable":
			if dbErr.SchemaName == "public" && dbErr.TableName == "normal_organizations" {
				target = ErrInvariantViolation
			}
		case "normal_organizations_base_invariant":
			if dbErr.SchemaName == "public" && dbErr.TableName == "organizations" && dbErr.ColumnName == "id" {
				target = ErrInvariantViolation
			}
		}
	case "23503":
		if dbErr.ConstraintName == "normal_organizations_organization_classification_fkey" &&
			dbErr.SchemaName == "public" && dbErr.TableName == "normal_organizations" {
			target = ErrInvariantViolation
		}
	case "22P02":
		if dbErr.ConstraintName == "" {
			target = ErrInvariantViolation
		}
	case "23502":
		if dbErr.ConstraintName == "" && dbErr.SchemaName == "public" {
			switch dbErr.TableName + "." + dbErr.ColumnName {
			case "organizations.id",
				"organizations.classification",
				"organizations.display_name",
				"organizations.canonical_name",
				"organizations.lifecycle",
				"organizations.created_at",
				"organizations.updated_at",
				"normal_organizations.organization_id",
				"normal_organizations.organization_classification",
				"normal_organizations.corporate_mapping_key",
				"normal_organizations.iana_time_zone":
				target = ErrInvariantViolation
			}
		}
	}
	if target == nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%w: %s: %w", target, operation, err)
}
