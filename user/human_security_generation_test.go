package user

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestValidateLoadedHumanSecurityGeneration(t *testing.T) {
	validUserID := uuid.New()
	tests := []struct {
		name  string
		state *HumanSecurityGeneration
		valid bool
	}{
		{name: "valid", state: &HumanSecurityGeneration{UserID: validUserID, Generation: 1}, valid: true},
		{name: "nil state"},
		{name: "nil User identity", state: &HumanSecurityGeneration{Generation: 1}},
		{name: "zero generation", state: &HumanSecurityGeneration{UserID: validUserID}},
		{name: "negative generation", state: &HumanSecurityGeneration{UserID: validUserID, Generation: -1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateLoadedHumanSecurityGeneration(test.state)
			if test.valid {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, ErrHumanSecurityGenerationInvariantViolation) {
				t.Fatalf("validate loaded state error = %v, want invariant violation", err)
			}
		})
	}
}

func TestHumanSecurityGenerationInvalidInputsDoNotIssueSQL(t *testing.T) {
	store := new(Store)
	ctx := context.Background()
	validUserID := uuid.New()

	if _, err := store.CreateHumanSecurityGeneration(ctx, uuid.Nil); !errors.Is(err, ErrInvalidHumanSecurityGenerationInput) {
		t.Fatalf("nil-ID create error = %v", err)
	}
	if _, err := store.FindHumanSecurityGeneration(ctx, uuid.Nil); !errors.Is(err, ErrInvalidHumanSecurityGenerationInput) {
		t.Fatalf("nil-ID find error = %v", err)
	}
	for _, input := range []AdvanceHumanSecurityGenerationInput{
		{ExpectedGeneration: 1},
		{UserID: validUserID},
		{UserID: validUserID, ExpectedGeneration: -1},
		{UserID: validUserID, ExpectedGeneration: math.MaxInt64},
	} {
		if _, err := store.AdvanceHumanSecurityGeneration(ctx, input); !errors.Is(err, ErrInvalidHumanSecurityGenerationInput) {
			t.Fatalf("advance input %#v error = %v", input, err)
		}
	}
}

func TestMapHumanSecurityGenerationWriteError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "canceled", err: context.Canceled, want: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded, want: context.DeadlineExceeded},
		{
			name: "duplicate",
			err: &pgconn.PgError{
				Code: "23505", SchemaName: "public", TableName: "user_human_security_generations",
				ConstraintName: "user_human_security_generations_pkey",
			},
			want: ErrHumanSecurityGenerationConflict,
		},
		{
			name: "missing User",
			err: &pgconn.PgError{
				Code: "23503", SchemaName: "public", TableName: "user_human_security_generations",
				ConstraintName: "user_human_security_generations_user_id_fkey",
			},
			want: ErrInvalidHumanSecurityGenerationInput,
		},
		{
			name: "invariant",
			err: &pgconn.PgError{
				Code: "23514", SchemaName: "public", TableName: "user_human_security_generations",
				ConstraintName: "user_human_security_generations_generation_step",
			},
			want: ErrHumanSecurityGenerationInvariantViolation,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := mapHumanSecurityGenerationWriteError("test operation", test.err)
			if !errors.Is(got, test.want) {
				t.Fatalf("mapped error = %v, want %v", got, test.want)
			}
			var source, mapped *pgconn.PgError
			if errors.As(test.err, &source) && (!errors.As(got, &mapped) || mapped != source) {
				t.Fatalf("mapped error does not retain original PostgreSQL error: %v", got)
			}
		})
	}
}
