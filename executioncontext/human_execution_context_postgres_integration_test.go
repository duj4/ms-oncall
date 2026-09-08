package executioncontext

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/migrate"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

const humanExecutionContextPostgresEnableEnv = "MS_ONCALL_CORE_MIGRATION_TEST_POSTGRES_ENABLE"

func TestPostgresHumanExecutionContextSingleStatementLinearization(t *testing.T) {
	db := newHumanExecutionContextPostgresDatabase(t)
	db.SetMaxOpenConns(4)
	store := organization.NewStore(db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	organizationA, err := store.CreateNormal(ctx, organization.CreateNormalOrganizationInput{
		DisplayName:         "Admission Organization A",
		CanonicalName:       "admission.organization-a",
		CorporateMappingKey: "admission:organization-a",
		TimeZone:            "Asia/Shanghai",
	})
	if err != nil {
		t.Fatal(err)
	}
	organizationB, err := store.CreateNormal(ctx, organization.CreateNormalOrganizationInput{
		DisplayName:         "Admission Organization B",
		CanonicalName:       "admission.organization-b",
		CorporateMappingKey: "admission:organization-b",
		TimeZone:            "Asia/Shanghai",
	})
	if err != nil {
		t.Fatal(err)
	}

	userID := uuid.New()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO public.users (id, name, email, role)
		VALUES ($1, 'Admission User', '', 'user')
	`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUserOrganizationAssignment(ctx, organization.CreateUserOrganizationAssignmentInput{
		UserID: userID,
		UserOrganizationAssignmentValues: organization.UserOrganizationAssignmentValues{
			EffectiveOrganizationID:             organizationA.ID,
			EffectiveOrganizationClassification: organization.ClassificationNormal,
			Role:                                organization.OrganizationRoleMember,
			MappingOutcome:                      organization.MappingOutcomeExactlyOne,
			Evaluation: organization.AssignmentEvaluation{
				AuthoritativeEvaluatedAt: time.Date(2026, time.September, 8, 8, 0, 0, 0, time.UTC),
				SourceConfigVersion:      "admission-linearization-v1",
				MatchedCount:             1,
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	sessionID := uuid.New()
	requestContext := permission.UserSourceContext(ctx, userID.String(), permission.RoleUser, &permission.SourceInfo{
		Type: permission.SourceTypeAuthProvider,
		ID:   sessionID.String(),
	})
	requester, err := auth.NewRequester(userID.String(), sessionID.String())
	if err != nil {
		t.Fatal(err)
	}
	requestContext = auth.WithRequester(requestContext, requester)
	constructor, err := NewHumanExecutionContextConstructor(store)
	if err != nil {
		t.Fatal(err)
	}

	admittedA := mustConstructHumanExecutionContext(t, constructor, requestContext, organizationA.ID)

	// B commits before the next authority statement begins, so the statement
	// must return B and cannot successfully return stale A.
	updateAdmissionAssignment(t, ctx, db, userID, organizationB.ID, organization.OrganizationRoleAdmin)
	admittedB := mustConstructHumanOrganization(t, constructor, requestContext, organizationB.ID)
	if admittedB == organizationA.ID {
		t.Fatal("admission returned stale Organization A after B committed")
	}

	updateAdmissionAssignment(t, ctx, db, userID, organizationA.ID, organization.OrganizationRoleMember)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.user_organization_assignments
		SET effective_organization_id = $2,
			effective_organization_classification = 'NORMAL',
			effective_normal_organization_id = $2,
			organization_role = 'ORG_ADMIN'
		WHERE user_id = $1
	`, userID, organizationB.ID); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}

	// B is deliberately uncommitted while the one admission statement observes
	// A. Once that statement returns, its finite request-bound value is stable.
	observedA := mustConstructHumanExecutionContext(t, constructor, requestContext, organizationA.ID)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got, present := observedA.EffectiveOrganizationID(); !present || got != organizationA.ID {
		t.Fatalf("admitted A changed after B committed: (%s, %t)", got, present)
	}

	// Neither an inherited request-bound value nor the identity-only Requester
	// supplies Organization state to the next admission observation.
	staleContext := WithExecutionContext(requestContext, observedA)
	mustConstructHumanOrganization(t, constructor, staleContext, organizationB.ID)

	// The first admitted value also remains an immutable A observation.
	if got, present := admittedA.EffectiveOrganizationID(); !present || got != organizationA.ID {
		t.Fatalf("earlier admitted A changed after later observations: (%s, %t)", got, present)
	}

	defaultID := uuid.MustParse(organization.DefaultOrganizationID)
	if _, err := db.ExecContext(ctx, `
		UPDATE public.user_organization_assignments
		SET effective_organization_id = $2,
			effective_organization_classification = 'DEFAULT',
			effective_normal_organization_id = NULL,
			organization_role = 'NONE',
			mapping_outcome = 'ZERO',
			matched_count = 0
		WHERE user_id = $1
	`, userID, defaultID); err != nil {
		t.Fatal(err)
	}
	if value, err := constructor.Construct(WithExecutionContext(requestContext, observedA)); !errors.Is(err, ErrHumanExecutionContextUnavailable) || value.Valid() {
		t.Fatalf("non-operational current truth with inherited A = (%#v, %v), want unavailable", value, err)
	}
}

func mustConstructHumanOrganization(t *testing.T, constructor *HumanExecutionContextConstructor, ctx context.Context, want uuid.UUID) uuid.UUID {
	t.Helper()
	value := mustConstructHumanExecutionContext(t, constructor, ctx, want)
	got, _ := value.EffectiveOrganizationID()
	return got
}

func mustConstructHumanExecutionContext(t *testing.T, constructor *HumanExecutionContextConstructor, ctx context.Context, want uuid.UUID) ExecutionContext {
	t.Helper()
	value, err := constructor.Construct(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, present := value.EffectiveOrganizationID()
	if !value.Valid() || !present || got != want {
		t.Fatalf("Construct effective Organization = (%s, %t), want %s", got, present, want)
	}
	return value
}

func updateAdmissionAssignment(t *testing.T, ctx context.Context, db *sql.DB, userID, organizationID uuid.UUID, role organization.OrganizationRole) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `
		UPDATE public.user_organization_assignments
		SET effective_organization_id = $2,
			effective_organization_classification = 'NORMAL',
			effective_normal_organization_id = $2,
			organization_role = $3
		WHERE user_id = $1
	`, userID, organizationID, role); err != nil {
		t.Fatal(err)
	}
}

func newHumanExecutionContextPostgresDatabase(t *testing.T) *sql.DB {
	t.Helper()
	if os.Getenv(humanExecutionContextPostgresEnableEnv) != "1" {
		t.Skipf("set %s=1 to run human ExecutionContext PostgreSQL integration tests", humanExecutionContextPostgresEnableEnv)
	}
	baseURL := os.Getenv("DB_URL")
	if baseURL == "" {
		t.Fatal("DB_URL must be configured for human ExecutionContext PostgreSQL integration tests")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse DB_URL: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		t.Fatalf("connect to PostgreSQL integration server: %v", err)
	}
	var random [4]byte
	if _, err := rand.Read(random[:]); err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	databaseName := fmt.Sprintf("msoc_execution_context_%d_%s", time.Now().Unix(), hex.EncodeToString(random[:]))
	quotedName := pgx.Identifier{databaseName}.Sanitize()
	if _, err := admin.Exec(ctx, "create database "+quotedName); err != nil {
		admin.Close(ctx)
		t.Fatalf("create human ExecutionContext PostgreSQL database: %v", err)
	}
	if err := admin.Close(ctx); err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + databaseName
	testURL := parsed.String()

	if _, err := migrate.ApplyAll(ctx, testURL); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", testURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close human ExecutionContext PostgreSQL database: %v", err)
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		cleanup, err := pgx.Connect(cleanupCtx, baseURL)
		if err != nil {
			t.Errorf("connect for human ExecutionContext PostgreSQL cleanup: %v", err)
			return
		}
		defer cleanup.Close(context.Background())
		if _, err := cleanup.Exec(cleanupCtx, "drop database if exists "+quotedName+" with (force)"); err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("drop human ExecutionContext PostgreSQL database: %v", err)
		}
	})
	return db
}
