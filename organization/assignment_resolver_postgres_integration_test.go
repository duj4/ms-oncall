package organization

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPostgresOrganizationAssignmentResolverDeterministicMappingAndNoMutation(t *testing.T) {
	db := newOrganizationPostgresDatabase(t)
	store := NewStore(db)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	createNormal := func(displayName, canonicalName, corporateKey string) *NormalOrganization {
		t.Helper()
		org, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
			DisplayName:         displayName,
			CanonicalName:       canonicalName,
			CorporateMappingKey: corporateKey,
			TimeZone:            "Asia/Shanghai",
		})
		if err != nil {
			t.Fatal(err)
		}
		return org
	}

	normalA := createNormal("Resolver Normal A", "resolver.normal-a", "resolver:normal-a")
	normalB := createNormal("Resolver Normal B", "resolver.normal-b", "resolver:normal-b")
	normalC := createNormal("Resolver Normal C", "resolver.normal-c", "resolver:normal-c")
	normalD := createNormal("Resolver Normal D", "resolver.normal-d", "resolver:normal-d")

	defaultOrg, err := store.FindDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Persist one accepted assignment as setup so resolver calls prove both that
	// no assignment is created and that an existing assignment is not updated.
	userID := insertAssignmentTestUser(t, ctx, db, "Resolver Non-Mutation User")
	evaluatedAt := time.Date(2026, time.September, 2, 15, 0, 0, 0, time.UTC)
	assignmentValues := createAssignmentTestValues(
		normalA.ID,
		ClassificationNormal,
		OrganizationRoleMember,
		MappingOutcomeExactlyOne,
		1,
		evaluatedAt,
		"preexisting-assignment-v1",
	)
	assignmentBefore, err := store.CreateUserOrganizationAssignment(ctx, CreateUserOrganizationAssignmentInput{
		UserID:                           userID,
		UserOrganizationAssignmentValues: assignmentValues,
	})
	if err != nil {
		t.Fatal(err)
	}
	var assignmentRowsBefore int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.user_organization_assignments`).Scan(&assignmentRowsBefore); err != nil {
		t.Fatal(err)
	}

	organizationIDs := []uuid.UUID{normalA.ID, normalB.ID, normalC.ID, normalD.ID}
	organizationsBefore := make(map[uuid.UUID]*NormalOrganization, len(organizationIDs))
	for _, id := range organizationIDs {
		org, err := store.FindNormalByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		organizationsBefore[id] = org
	}

	resolver, err := NewOrganizationAssignmentResolver(store, OrganizationAssignmentResolverConfig{
		SourceConfigVersion: "postgres-resolver-config-v1",
		Rules: []OrganizationAssignmentMappingRule{
			{EnterpriseMappingIdentifier: "verified:normal-a", CorporateMappingKey: "resolver:normal-a"},
			{EnterpriseMappingIdentifier: "verified:alias-a", CorporateMappingKey: "resolver:normal-a"},
			{EnterpriseMappingIdentifier: "verified:normal-b", CorporateMappingKey: "resolver:normal-b"},
			{EnterpriseMappingIdentifier: "verified:normal-c", CorporateMappingKey: "resolver:normal-c"},
			{EnterpriseMappingIdentifier: "verified:normal-d", CorporateMappingKey: "resolver:normal-d"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	assertDecision := func(inputs []string, outcome MappingOutcome, count int, id uuid.UUID, classification Classification) {
		t.Helper()
		decision, err := resolver.Resolve(ctx, inputs)
		if err != nil {
			t.Fatal(err)
		}
		if decision.MappingOutcome != outcome || decision.MatchedCount != count ||
			decision.EffectiveOrganizationID != id ||
			decision.EffectiveOrganizationClassification != classification ||
			decision.SourceConfigVersion != "postgres-resolver-config-v1" {
			t.Fatalf("decision = %#v, want outcome=%s count=%d id=%s classification=%s",
				decision, outcome, count, id, classification)
		}
	}

	assertDecision([]string{"verified:normal-a"}, MappingOutcomeExactlyOne, 1, normalA.ID, ClassificationNormal)
	assertDecision([]string{"verified:alias-a", "verified:normal-a"}, MappingOutcomeExactlyOne, 1, normalA.ID, ClassificationNormal)
	assertDecision([]string{"verified:normal-b", "verified:normal-a"}, MappingOutcomeMultiple, 2, defaultOrg.ID, ClassificationDefault)
	assertDecision([]string{"verified:unknown"}, MappingOutcomeZero, 0, defaultOrg.ID, ClassificationDefault)
	assertDecision([]string{"verified:normal-c"}, MappingOutcomeExactlyOne, 1, normalC.ID, ClassificationNormal)
	assertDecision([]string{"verified:normal-d"}, MappingOutcomeExactlyOne, 1, normalD.ID, ClassificationNormal)
	assertDecision([]string{"verified:normal-c", "verified:normal-a"}, MappingOutcomeMultiple, 2, defaultOrg.ID, ClassificationDefault)

	missingResolver, err := NewOrganizationAssignmentResolver(store, OrganizationAssignmentResolverConfig{
		SourceConfigVersion: "postgres-missing-target-v1",
		Rules: []OrganizationAssignmentMappingRule{{
			EnterpriseMappingIdentifier: "verified:missing",
			CorporateMappingKey:         "resolver:missing",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missingResolver.Resolve(ctx, []string{"verified:missing"}); !errors.Is(err, ErrStaleOrganizationAssignmentResolverConfiguration) {
		t.Fatalf("missing configured target error = %v, want stale resolver configuration", err)
	}

	assignmentAfter, err := store.FindUserOrganizationAssignment(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	assertUserOrganizationAssignmentEqual(t, assignmentAfter, assignmentBefore)
	var assignmentRowsAfter int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.user_organization_assignments`).Scan(&assignmentRowsAfter); err != nil {
		t.Fatal(err)
	}
	if assignmentRowsAfter != assignmentRowsBefore {
		t.Fatalf("resolver changed assignment row count from %d to %d", assignmentRowsBefore, assignmentRowsAfter)
	}

	for _, id := range organizationIDs {
		orgAfter, err := store.FindNormalByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(orgAfter, organizationsBefore[id]) {
			t.Fatalf("resolver mutated Organization %s: before=%#v after=%#v", id, organizationsBefore[id], orgAfter)
		}
	}
}
