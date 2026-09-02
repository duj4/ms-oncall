package organization

import (
	"context"
	"crypto/sha256"
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

	activeA := createNormal("Resolver Active A", "resolver.active-a", "resolver:active-a")
	activeB := createNormal("Resolver Active B", "resolver.active-b", "resolver:active-b")
	suspended := createNormal("Resolver Suspended", "resolver.suspended", "resolver:suspended")
	retired := createNormal("Resolver Retired", "resolver.retired", "resolver:retired")

	updatedSuspended, err := store.TransitionLifecycle(ctx, suspended.ID, LifecycleSuspended)
	if err != nil {
		t.Fatal(err)
	}
	suspended.Organization = *updatedSuspended
	updatedRetired, err := store.TransitionLifecycle(ctx, retired.ID, LifecycleRetired)
	if err != nil {
		t.Fatal(err)
	}
	retired.Organization = *updatedRetired

	defaultOrg, err := store.FindDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Persist one accepted assignment as setup so resolver calls prove both that
	// no assignment is created and that an existing assignment is not updated.
	userID := insertAssignmentTestUser(t, ctx, db, "Resolver Non-Mutation User")
	evaluatedAt := time.Date(2026, time.September, 2, 15, 0, 0, 0, time.UTC)
	assignmentValues := createAssignmentTestValues(
		activeA.ID,
		ClassificationNormal,
		AssignmentStateActive,
		OrganizationRoleMember,
		MappingOutcomeExactlyOne,
		1,
		evaluatedAt,
		"preexisting-assignment-v1",
	)
	assignmentValues.Evaluation.EvidenceDigest = sha256.Sum256([]byte("preexisting assignment evidence"))
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

	organizationIDs := []uuid.UUID{activeA.ID, activeB.ID, suspended.ID, retired.ID}
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
			{EnterpriseMappingIdentifier: "verified:active-a", CorporateMappingKey: "resolver:active-a"},
			{EnterpriseMappingIdentifier: "verified:alias-a", CorporateMappingKey: "resolver:active-a"},
			{EnterpriseMappingIdentifier: "verified:active-b", CorporateMappingKey: "resolver:active-b"},
			{EnterpriseMappingIdentifier: "verified:suspended", CorporateMappingKey: "resolver:suspended"},
			{EnterpriseMappingIdentifier: "verified:retired", CorporateMappingKey: "resolver:retired"},
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

	assertDecision([]string{"verified:active-a"}, MappingOutcomeExactlyOne, 1, activeA.ID, ClassificationNormal)
	assertDecision([]string{"verified:alias-a", "verified:active-a"}, MappingOutcomeExactlyOne, 1, activeA.ID, ClassificationNormal)
	assertDecision([]string{"verified:active-b", "verified:active-a"}, MappingOutcomeMultiple, 2, defaultOrg.ID, ClassificationDefault)
	assertDecision([]string{"verified:unknown"}, MappingOutcomeZero, 0, defaultOrg.ID, ClassificationDefault)
	assertDecision([]string{"verified:suspended"}, MappingOutcomeZero, 0, defaultOrg.ID, ClassificationDefault)
	assertDecision([]string{"verified:retired"}, MappingOutcomeZero, 0, defaultOrg.ID, ClassificationDefault)
	assertDecision([]string{"verified:suspended", "verified:active-a"}, MappingOutcomeExactlyOne, 1, activeA.ID, ClassificationNormal)

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
