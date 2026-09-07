package executioncontext

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

func TestExecutionContextContextTransportUsesDefensiveCopies(t *testing.T) {
	fixture := newHumanExecutionContextFixture(t)
	value, err := fixture.constructor(t).Construct(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	base := context.Background()
	if got := WithExecutionContext(base, ExecutionContext{}); got != base || ExecutionContextFromContext(got) != nil {
		t.Fatal("invalid ExecutionContext was installed")
	}
	if WithExecutionContext(nil, value) != nil || ExecutionContextFromContext(nil) != nil {
		t.Fatal("nil context exposed or installed ExecutionContext")
	}
	ctx := WithExecutionContext(base, value)
	first := ExecutionContextFromContext(ctx)
	if first == nil || !first.Valid() {
		t.Fatal("valid ExecutionContext was not returned")
	}
	first.valid = false
	second := ExecutionContextFromContext(ctx)
	if second == nil || !second.Valid() {
		t.Fatal("returned copy mutated stored ExecutionContext")
	}
}

func TestHumanExecutionContextHTTPComposition(t *testing.T) {
	t.Run("valid current authority installed", func(t *testing.T) {
		fixture := newHumanExecutionContextFixture(t)
		var delivered *ExecutionContext
		handler := fixture.constructor(t).WrapHandler(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
			delivered = ExecutionContextFromContext(req.Context())
		}))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil).WithContext(fixture.ctx))
		if delivered == nil || !delivered.Valid() {
			t.Fatal("valid request did not receive ExecutionContext")
		}
		if id, present := delivered.EffectiveOrganizationID(); !present || id != fixture.orgID {
			t.Fatalf("delivered Organization = (%s, %t)", id, present)
		}
	})

	t.Run("missing Requester continues without authority", func(t *testing.T) {
		fixture := newHumanExecutionContextFixture(t)
		var delivered *ExecutionContext
		handler := fixture.constructor(t).WrapHandler(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
			delivered = ExecutionContextFromContext(req.Context())
		}))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		if delivered != nil || fixture.users.calls != 0 || fixture.orgs.assignmentCalls != 0 || fixture.orgs.normalCalls != 0 {
			t.Fatalf("unauthenticated request received authority or caused reads: %#v", delivered)
		}
	})

	t.Run("failed reconstruction shadows inherited authority", func(t *testing.T) {
		fixture := newHumanExecutionContextFixture(t)
		prior, err := fixture.constructor(t).Construct(fixture.ctx)
		if err != nil {
			t.Fatal(err)
		}
		fixture.orgs.assignment.MappingOutcome = organization.MappingOutcomeZero
		fixture.orgs.assignment.EffectiveOrganizationID = uuid.MustParse(organization.DefaultOrganizationID)
		fixture.orgs.assignment.EffectiveOrganizationClassification = organization.ClassificationDefault
		fixture.orgs.assignment.Role = organization.OrganizationRoleNone
		fixture.orgs.assignment.Evaluation.MatchedCount = 0
		ctx := WithExecutionContext(fixture.ctx, prior)
		var delivered *ExecutionContext
		handler := fixture.constructor(t).WrapHandler(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
			delivered = ExecutionContextFromContext(req.Context())
		}))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx))
		if delivered != nil {
			t.Fatalf("failed reconstruction reused inherited authority: %#v", delivered)
		}
	})
}
