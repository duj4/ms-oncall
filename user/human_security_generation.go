package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

const InitialHumanSecurityGeneration int64 = 1

var (
	// ErrHumanSecurityGenerationNotFound indicates that no explicit human
	// security generation is persisted for the requested global User.
	ErrHumanSecurityGenerationNotFound = errors.New("human security generation not found")
	// ErrHumanSecurityGenerationConflict indicates that explicit human security
	// generation state already exists for the requested global User.
	ErrHumanSecurityGenerationConflict = errors.New("human security generation conflict")
	// ErrStaleHumanSecurityGeneration indicates that a guarded advance lost a
	// race with a newer human security generation.
	ErrStaleHumanSecurityGeneration = errors.New("stale human security generation")
	// ErrInvalidHumanSecurityGenerationInput indicates invalid caller-supplied
	// persistence input.
	ErrInvalidHumanSecurityGenerationInput = errors.New("invalid human security generation input")
	// ErrHumanSecurityGenerationInvariantViolation indicates contradictory or
	// invalid durable human security generation state.
	ErrHumanSecurityGenerationInvariantViolation = errors.New("human security generation persistence invariant violation")
)

// HumanSecurityGeneration is the optional, explicitly persisted monotonic
// human security authority evidence for one global User.
type HumanSecurityGeneration struct {
	UserID     uuid.UUID
	Generation int64
}

// AdvanceHumanSecurityGenerationInput identifies the exact persisted
// generation that may be advanced once.
type AdvanceHumanSecurityGenerationInput struct {
	UserID             uuid.UUID
	ExpectedGeneration int64
}

type humanSecurityGenerationScanner interface {
	Scan(dest ...any) error
}

func scanHumanSecurityGeneration(row humanSecurityGenerationScanner) (*HumanSecurityGeneration, error) {
	var state HumanSecurityGeneration
	if err := row.Scan(&state.UserID, &state.Generation); err != nil {
		return nil, err
	}
	if err := validateLoadedHumanSecurityGeneration(&state); err != nil {
		return nil, err
	}
	return &state, nil
}

func validateLoadedHumanSecurityGeneration(state *HumanSecurityGeneration) error {
	if state == nil || state.UserID == uuid.Nil {
		return fmt.Errorf("%w: missing global User identity", ErrHumanSecurityGenerationInvariantViolation)
	}
	if state.Generation <= 0 {
		return fmt.Errorf("%w: generation must be positive", ErrHumanSecurityGenerationInvariantViolation)
	}
	return nil
}

// CreateHumanSecurityGeneration explicitly persists initial generation one for
// a global User. It performs no lookup, backfill, or other User mutation.
func (s *Store) CreateHumanSecurityGeneration(ctx context.Context, userID uuid.UUID) (*HumanSecurityGeneration, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("%w: User ID is required", ErrInvalidHumanSecurityGenerationInput)
	}

	state, err := scanHumanSecurityGeneration(s.db.QueryRowContext(ctx, `
		INSERT INTO public.user_human_security_generations (
			user_id, human_security_generation
		) VALUES ($1, $2)
		RETURNING user_id, human_security_generation
	`, userID, InitialHumanSecurityGeneration))
	if err != nil {
		return nil, mapHumanSecurityGenerationWriteError("create human security generation", err)
	}
	return state, nil
}

// FindHumanSecurityGeneration returns only explicitly persisted state. Missing
// state is not created and is not interpreted as generation one.
func (s *Store) FindHumanSecurityGeneration(ctx context.Context, userID uuid.UUID) (*HumanSecurityGeneration, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("%w: User ID is required", ErrInvalidHumanSecurityGenerationInput)
	}

	state, err := scanHumanSecurityGeneration(s.db.QueryRowContext(ctx, `
		SELECT user_id, human_security_generation
		FROM public.user_human_security_generations
		WHERE user_id = $1
	`, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrHumanSecurityGenerationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read human security generation: %w", err)
	}
	return state, nil
}

// AdvanceHumanSecurityGeneration atomically advances exactly one generation
// when ExpectedGeneration is current. A stale guard is never retried.
func (s *Store) AdvanceHumanSecurityGeneration(ctx context.Context, input AdvanceHumanSecurityGenerationInput) (*HumanSecurityGeneration, error) {
	if input.UserID == uuid.Nil || input.ExpectedGeneration <= 0 || input.ExpectedGeneration == math.MaxInt64 {
		return nil, fmt.Errorf("%w: User ID and incrementable expected generation are required", ErrInvalidHumanSecurityGenerationInput)
	}

	state, err := scanHumanSecurityGeneration(s.db.QueryRowContext(ctx, `
		UPDATE public.user_human_security_generations
		SET human_security_generation = $2 + 1
		WHERE user_id = $1 AND human_security_generation = $2
		RETURNING user_id, human_security_generation
	`, input.UserID, input.ExpectedGeneration))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, s.classifyHumanSecurityGenerationGuardMiss(ctx, input.UserID, input.ExpectedGeneration)
	}
	if err != nil {
		return nil, mapHumanSecurityGenerationWriteError("advance human security generation", err)
	}
	return state, nil
}

func (s *Store) classifyHumanSecurityGenerationGuardMiss(ctx context.Context, userID uuid.UUID, expectedGeneration int64) error {
	var currentGeneration int64
	err := s.db.QueryRowContext(ctx, `
		SELECT human_security_generation
		FROM public.user_human_security_generations
		WHERE user_id = $1
	`, userID).Scan(&currentGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrHumanSecurityGenerationNotFound
	}
	if err != nil {
		return fmt.Errorf("classify guarded human security generation advance: %w", err)
	}
	if currentGeneration <= 0 {
		return fmt.Errorf("%w: current generation must be positive", ErrHumanSecurityGenerationInvariantViolation)
	}
	if currentGeneration != expectedGeneration {
		return ErrStaleHumanSecurityGeneration
	}
	return fmt.Errorf("%w: guarded advance affected no row", ErrHumanSecurityGenerationInvariantViolation)
}

func mapHumanSecurityGenerationWriteError(operation string, err error) error {
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
		if dbErr.SchemaName == "public" &&
			dbErr.TableName == "user_human_security_generations" &&
			dbErr.ConstraintName == "user_human_security_generations_pkey" {
			target = ErrHumanSecurityGenerationConflict
		}
	case "23503":
		if dbErr.SchemaName == "public" &&
			dbErr.TableName == "user_human_security_generations" &&
			dbErr.ConstraintName == "user_human_security_generations_user_id_fkey" {
			target = ErrInvalidHumanSecurityGenerationInput
		}
	case "23514", "23502":
		if dbErr.SchemaName == "public" && dbErr.TableName == "user_human_security_generations" {
			target = ErrHumanSecurityGenerationInvariantViolation
		}
	}
	if target == nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%w: %s: %w", target, operation, err)
}
