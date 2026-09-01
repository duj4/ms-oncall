package organization

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestCanonicalTimeZone(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "canonical", input: "Asia/Shanghai", want: "Asia/Shanghai"},
		{name: "existing alias canonicalized", input: "Asia/Chongqing", want: "Asia/Shanghai"},
		{name: "UTC alias canonicalized", input: "UTC", want: "Etc/UTC"},
		{name: "raw offset", input: "+08:00", wantErr: true},
		{name: "local pseudo-zone", input: "Local", wantErr: true},
		{name: "unknown", input: "Mars/Olympus_Mons", wantErr: true},
		{name: "empty", input: "", wantErr: true},
		{name: "untrimmed", input: " Asia/Shanghai ", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := canonicalTimeZone(test.input)
			if test.wantErr {
				if !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("canonicalTimeZone error = %v, want ErrInvalidInput", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("canonicalTimeZone = %q, want %q", got, test.want)
			}
		})
	}
}

func TestLifecycleTransitionPolicy(t *testing.T) {
	states := []Lifecycle{LifecycleActive, LifecycleSuspended, LifecycleRetired}
	allowed := map[[2]Lifecycle]bool{
		{LifecycleActive, LifecycleActive}:       true,
		{LifecycleActive, LifecycleSuspended}:    true,
		{LifecycleActive, LifecycleRetired}:      true,
		{LifecycleSuspended, LifecycleActive}:    true,
		{LifecycleSuspended, LifecycleSuspended}: true,
		{LifecycleSuspended, LifecycleRetired}:   true,
		{LifecycleRetired, LifecycleRetired}:     true,
	}
	for _, from := range states {
		for _, to := range states {
			if got := lifecycleTransitionAllowed(from, to); got != allowed[[2]Lifecycle{from, to}] {
				t.Errorf("lifecycleTransitionAllowed(%s, %s) = %v", from, to, got)
			}
		}
	}
	if lifecycleTransitionAllowed("UNKNOWN", LifecycleActive) {
		t.Fatal("unknown lifecycle was accepted")
	}
}

func TestValidateCreateInput(t *testing.T) {
	valid := CreateNormalOrganizationInput{
		DisplayName:         "Example Organization",
		CanonicalName:       "example.organization",
		CorporateMappingKey: "corp:example",
		TimeZone:            "Asia/Chongqing",
	}
	got, err := validateCreateInput(valid)
	if err != nil {
		t.Fatal(err)
	}
	if got.TimeZone != "Asia/Shanghai" {
		t.Fatalf("canonical time zone = %q, want Asia/Shanghai", got.TimeZone)
	}

	tests := []struct {
		name   string
		mutate func(*CreateNormalOrganizationInput)
	}{
		{name: "blank display", mutate: func(v *CreateNormalOrganizationInput) { v.DisplayName = "  " }},
		{name: "blank canonical", mutate: func(v *CreateNormalOrganizationInput) { v.CanonicalName = "" }},
		{name: "untrimmed canonical", mutate: func(v *CreateNormalOrganizationInput) { v.CanonicalName = " example " }},
		{name: "blank mapping", mutate: func(v *CreateNormalOrganizationInput) { v.CorporateMappingKey = "" }},
		{name: "untrimmed mapping", mutate: func(v *CreateNormalOrganizationInput) { v.CorporateMappingKey = " corp " }},
		{name: "invalid time zone", mutate: func(v *CreateNormalOrganizationInput) { v.TimeZone = "+08:00" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			test.mutate(&input)
			if _, err := validateCreateInput(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("validateCreateInput error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestValidateLoadedOrganizationFailsClosed(t *testing.T) {
	now := time.Now()
	valid := Organization{
		ID:             uuid.New(),
		Classification: ClassificationNormal,
		DisplayName:    "Example",
		CanonicalName:  "example",
		Lifecycle:      LifecycleActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := validateLoadedOrganization(&valid); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Organization)
	}{
		{name: "nil ID", mutate: func(v *Organization) { v.ID = uuid.Nil }},
		{name: "unknown classification", mutate: func(v *Organization) { v.Classification = "UNKNOWN" }},
		{name: "blank display", mutate: func(v *Organization) { v.DisplayName = " " }},
		{name: "untrimmed canonical", mutate: func(v *Organization) { v.CanonicalName = " bad " }},
		{name: "unknown lifecycle", mutate: func(v *Organization) { v.Lifecycle = "UNKNOWN" }},
		{name: "zero creation time", mutate: func(v *Organization) { v.CreatedAt = time.Time{} }},
		{name: "audit time reversed", mutate: func(v *Organization) { v.UpdatedAt = now.Add(-time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			org := valid
			test.mutate(&org)
			if err := validateLoadedOrganization(&org); !errors.Is(err, ErrInvariantViolation) {
				t.Fatalf("validateLoadedOrganization error = %v, want ErrInvariantViolation", err)
			}
		})
	}
}

func TestMapWriteError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantTarget error
	}{
		{name: "unique", err: &pgconn.PgError{Code: "23505"}, wantTarget: ErrConflict},
		{name: "lifecycle", err: &pgconn.PgError{Code: "23514", ConstraintName: "organizations_lifecycle_transition"}, wantTarget: ErrInvalidLifecycleTransition},
		{name: "check", err: &pgconn.PgError{Code: "23514"}, wantTarget: ErrInvariantViolation},
		{name: "foreign key", err: &pgconn.PgError{Code: "23503"}, wantTarget: ErrInvariantViolation},
		{name: "invalid enum", err: &pgconn.PgError{Code: "22P02"}, wantTarget: ErrInvariantViolation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := mapWriteError("test", test.err); !errors.Is(got, test.wantTarget) {
				t.Fatalf("mapWriteError = %v, want %v", got, test.wantTarget)
			}
		})
	}
}
