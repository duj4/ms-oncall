package executioncontext

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

func TestCurrentHumanAuthorityContextUsesDefensiveCopies(t *testing.T) {
	fixture := newCurrentHumanAuthorityFixture(t)
	authority, err := fixture.constructor(t).Construct(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}

	base := context.Background()
	if got := WithCurrentHumanAuthority(base, CurrentHumanAuthority{}); got != base || CurrentHumanAuthorityFromContext(got) != nil {
		t.Fatal("invalid CurrentHumanAuthority was installed")
	}
	if WithCurrentHumanAuthority(nil, authority) != nil || CurrentHumanAuthorityFromContext(nil) != nil {
		t.Fatal("nil context exposed or installed CurrentHumanAuthority")
	}

	ctx := WithCurrentHumanAuthority(base, authority)
	first := CurrentHumanAuthorityFromContext(ctx)
	if first == nil || !first.Valid() || first.ExecutionContext() == nil || first.Observation() == nil {
		t.Fatalf("CurrentHumanAuthorityFromContext = %#v, want valid defensive copy", first)
	}
	first.valid = false
	first.context.valid = false
	first.observation.valid = false
	second := CurrentHumanAuthorityFromContext(ctx)
	if second == nil || !second.Valid() || second.ExecutionContext() == nil || second.Observation() == nil {
		t.Fatal("mutating returned authority changed the stored context value")
	}
}

func TestCurrentHumanAuthorityHTTPComposition(t *testing.T) {
	tests := []struct {
		name            string
		prepare         func(*testing.T, *currentHumanAuthorityFixture)
		wantAuthority   bool
		wantUserReads   int
		wantAssignments int
		wantOrgs        int
		wantLegacyHuman bool
		wantIntegration bool
	}{
		{
			name: "valid authenticated human",
			prepare: func(*testing.T, *currentHumanAuthorityFixture) {
			},
			wantAuthority:   true,
			wantUserReads:   1,
			wantAssignments: 1,
			wantOrgs:        1,
			wantLegacyHuman: true,
		},
		{
			name: "anonymous",
			prepare: func(_ *testing.T, f *currentHumanAuthorityFixture) {
				f.ctx = context.Background()
			},
		},
		{
			name: "legacy permission metadata without Requester",
			prepare: func(_ *testing.T, f *currentHumanAuthorityFixture) {
				f.ctx = permission.UserSourceContext(context.Background(), f.userID.String(), permission.RoleUser, &permission.SourceInfo{
					Type: permission.SourceTypeAuthProvider,
					ID:   f.sessionID.String(),
				})
			},
			wantLegacyHuman: true,
		},
		{
			name: "integration context",
			prepare: func(_ *testing.T, f *currentHumanAuthorityFixture) {
				f.ctx = permission.ServiceSourceContext(context.Background(), uuid.NewString(), &permission.SourceInfo{
					Type: permission.SourceTypeIntegrationKey,
					ID:   uuid.NewString(),
				})
			},
			wantIntegration: true,
		},
		{
			name: "unavailable current assignment",
			prepare: func(_ *testing.T, f *currentHumanAuthorityFixture) {
				f.orgs.assignment.MappingOutcome = organization.MappingOutcomeZero
				f.orgs.assignment.EffectiveOrganizationID = uuid.MustParse(organization.DefaultOrganizationID)
				f.orgs.assignment.EffectiveOrganizationClassification = organization.ClassificationDefault
				f.orgs.assignment.Role = organization.OrganizationRoleNone
				f.orgs.assignment.Evaluation.MatchedCount = 0
			},
			wantUserReads:   1,
			wantAssignments: 1,
			wantLegacyHuman: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCurrentHumanAuthorityFixture(t)
			test.prepare(t, fixture)
			constructor := fixture.constructor(t)
			var delivered *CurrentHumanAuthority
			var deliveredExecutionContext *ExecutionContext
			var deliveredLegacyUserID, deliveredServiceID string
			var deliveredSource *permission.SourceInfo
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				nextCalled = true
				delivered = CurrentHumanAuthorityFromContext(req.Context())
				deliveredLegacyUserID = permission.UserID(req.Context())
				deliveredServiceID = permission.ServiceID(req.Context())
				deliveredSource = permission.Source(req.Context())
				if delivered != nil {
					deliveredExecutionContext = delivered.ExecutionContext()
				}
				w.WriteHeader(http.StatusNoContent)
			})
			req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil).WithContext(fixture.ctx)
			response := httptest.NewRecorder()

			constructor.WrapHandler(next).ServeHTTP(response, req)

			if !nextCalled || response.Code != http.StatusNoContent {
				t.Fatalf("downstream = (called:%t status:%d), want unchanged continuation with 204", nextCalled, response.Code)
			}
			if test.wantAuthority != (delivered != nil && delivered.Valid() && deliveredExecutionContext != nil && deliveredExecutionContext.Valid()) {
				t.Fatalf("delivered authority = %#v, ExecutionContext = %#v, want authority %t", delivered, deliveredExecutionContext, test.wantAuthority)
			}
			if fixture.users.calls != test.wantUserReads || fixture.orgs.assignmentCalls != test.wantAssignments || fixture.orgs.normalCalls != test.wantOrgs {
				t.Fatalf("durable reads = User:%d assignment:%d Organization:%d, want %d/%d/%d",
					fixture.users.calls, fixture.orgs.assignmentCalls, fixture.orgs.normalCalls,
					test.wantUserReads, test.wantAssignments, test.wantOrgs)
			}
			if test.wantLegacyHuman && (deliveredLegacyUserID != fixture.userID.String() || deliveredSource == nil || deliveredSource.Type != permission.SourceTypeAuthProvider) {
				t.Fatalf("legacy human context = (User:%q Source:%#v), want preserved AuthProvider User", deliveredLegacyUserID, deliveredSource)
			}
			if test.wantIntegration && (deliveredServiceID == "" || deliveredSource == nil || deliveredSource.Type != permission.SourceTypeIntegrationKey) {
				t.Fatalf("integration context = (Service:%q Source:%#v), want preserved IntegrationKey service", deliveredServiceID, deliveredSource)
			}
			if test.wantAuthority {
				requester := auth.RequesterFromContext(fixture.ctx)
				if requester == nil || delivered.Observation().SessionID() != requester.SessionID() || delivered.Observation().UserID() != requester.UserID() {
					t.Fatal("delivered authority did not preserve authenticated Requester identity")
				}
				observation := delivered.Observation()
				effectiveOrganizationID, hasOrganization := deliveredExecutionContext.EffectiveOrganizationID()
				assignmentGeneration, hasGeneration := deliveredExecutionContext.AssignmentGeneration()
				privileges := deliveredExecutionContext.Privileges()
				if !hasOrganization || effectiveOrganizationID != fixture.orgs.assignment.EffectiveOrganizationID ||
					!hasGeneration || assignmentGeneration != fixture.orgs.assignment.AssignmentGeneration ||
					privileges == nil || privileges.OrganizationRole() != fixture.orgs.assignment.Role ||
					observation == nil || observation.OrganizationLifecycle() != fixture.orgs.normal.Lifecycle {
					t.Fatal("delivered Organization identity, role, generation, or lifecycle did not come from current durable state")
				}
			}
		})
	}
}

func TestAuthenticationBoundaryClearsInheritedRequesterBeforeCurrentHumanAuthority(t *testing.T) {
	fixture := newCurrentHumanAuthorityFixture(t)
	constructor := fixture.constructor(t)
	precondition, err := constructor.Construct(fixture.ctx)
	if err != nil || !precondition.Valid() || precondition.ExecutionContext() == nil {
		t.Fatalf("exploit precondition authority = (%#v, %v), want valid inherited identity state", precondition, err)
	}
	fixture.users.calls = 0
	fixture.users.lastID = ""
	fixture.orgs.assignmentCalls = 0
	fixture.orgs.normalCalls = 0
	fixture.orgs.assignmentID = uuid.Nil
	fixture.orgs.normalID = uuid.Nil

	var requesterAfterAuthentication *auth.Requester
	var deliveredAuthority *CurrentHumanAuthority
	var deliveredExecutionContext *ExecutionContext
	var deliveredLegacyUserID string
	nextCalled := false
	authorityMiddleware := constructor.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		nextCalled = true
		deliveredAuthority = CurrentHumanAuthorityFromContext(req.Context())
		if deliveredAuthority != nil {
			deliveredExecutionContext = deliveredAuthority.ExecutionContext()
		}
		deliveredLegacyUserID = permission.UserID(req.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	afterAuthentication := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requesterAfterAuthentication = auth.RequesterFromContext(req.Context())
		authorityMiddleware.ServeHTTP(w, req)
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil).WithContext(fixture.ctx)
	response := httptest.NewRecorder()
	new(auth.Handler).WrapHandler(afterAuthentication).ServeHTTP(response, req)

	if !nextCalled || response.Code != http.StatusNoContent {
		t.Fatalf("downstream = (called:%t status:%d), want unchanged anonymous continuation with 204", nextCalled, response.Code)
	}
	if requesterAfterAuthentication != nil {
		t.Fatalf("Requester after authentication = %#v, want inherited identity cleared", requesterAfterAuthentication)
	}
	if deliveredAuthority != nil || deliveredExecutionContext != nil {
		t.Fatalf("downstream authority = (%#v, %#v), want no trusted inherited human authority", deliveredAuthority, deliveredExecutionContext)
	}
	if fixture.users.calls != 0 || fixture.orgs.assignmentCalls != 0 || fixture.orgs.normalCalls != 0 {
		t.Fatalf("inherited identity triggered durable authority reads = User:%d assignment:%d Organization:%d, want 0/0/0",
			fixture.users.calls, fixture.orgs.assignmentCalls, fixture.orgs.normalCalls)
	}
	if deliveredLegacyUserID != fixture.userID.String() {
		t.Fatalf("legacy User compatibility identity = %q, want preserved %q without typed authority", deliveredLegacyUserID, fixture.userID)
	}
}

func TestCurrentHumanAuthorityHTTPCompositionDoesNotReusePriorAuthority(t *testing.T) {
	validFixture := newCurrentHumanAuthorityFixture(t)
	prior, err := validFixture.constructor(t).Construct(validFixture.ctx)
	if err != nil {
		t.Fatal(err)
	}

	invalidFixture := newCurrentHumanAuthorityFixture(t)
	invalidFixture.orgs.normal.Lifecycle = organization.LifecycleSuspended
	invalidFixture.ctx = WithCurrentHumanAuthority(invalidFixture.ctx, prior)
	deliveredPrior := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		deliveredPrior = CurrentHumanAuthorityFromContext(req.Context()) != nil
	})
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil).WithContext(invalidFixture.ctx)
	invalidFixture.constructor(t).WrapHandler(next).ServeHTTP(httptest.NewRecorder(), req)
	if deliveredPrior {
		t.Fatal("unavailable current authority fell back to a prior context value")
	}
}
