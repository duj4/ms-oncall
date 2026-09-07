package executioncontext

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/user"
)

type fakeHumanUserReader struct {
	user   *user.User
	err    error
	calls  int
	lastID string
}

func (r *fakeHumanUserReader) FindOne(_ context.Context, id string) (*user.User, error) {
	r.calls++
	r.lastID = id
	if r.user == nil {
		return nil, r.err
	}
	value := *r.user
	return &value, r.err
}

type fakeHumanOrganizationReader struct {
	assignment      *organization.UserOrganizationAssignment
	assignmentErr   error
	normal          *organization.NormalOrganization
	normalErr       error
	assignmentCalls int
	normalCalls     int
	assignmentID    uuid.UUID
	normalID        uuid.UUID
}

func (r *fakeHumanOrganizationReader) FindUserOrganizationAssignment(_ context.Context, id uuid.UUID) (*organization.UserOrganizationAssignment, error) {
	r.assignmentCalls++
	r.assignmentID = id
	if r.assignment == nil {
		return nil, r.assignmentErr
	}
	value := *r.assignment
	return &value, r.assignmentErr
}

func (r *fakeHumanOrganizationReader) FindNormalByID(_ context.Context, id uuid.UUID) (*organization.NormalOrganization, error) {
	r.normalCalls++
	r.normalID = id
	if r.normal == nil {
		return nil, r.normalErr
	}
	value := *r.normal
	return &value, r.normalErr
}

type humanExecutionContextFixture struct {
	sessionID uuid.UUID
	userID    uuid.UUID
	orgID     uuid.UUID
	ctx       context.Context
	users     *fakeHumanUserReader
	orgs      *fakeHumanOrganizationReader
}

func newHumanExecutionContextFixture(t *testing.T) *humanExecutionContextFixture {
	t.Helper()
	sessionID := uuid.MustParse("5ad72c4f-92ed-4e42-b5a3-11359f6b5ac2")
	userID := uuid.MustParse("57accb9a-2985-48c7-8829-fac89c747a22")
	orgID := uuid.MustParse("70ca7d8d-6f35-45e8-9109-796b455d0e7b")
	evaluatedAt := time.Date(2026, time.September, 6, 2, 0, 0, 0, time.UTC)
	ctx := permission.UserSourceContext(
		context.Background(),
		userID.String(),
		permission.RoleUser,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: sessionID.String()},
	)
	requester, err := auth.NewRequester(userID.String(), sessionID.String())
	if err != nil {
		t.Fatal(err)
	}
	ctx = auth.WithRequester(ctx, requester)
	return &humanExecutionContextFixture{
		sessionID: sessionID,
		userID:    userID,
		orgID:     orgID,
		ctx:       ctx,
		users: &fakeHumanUserReader{user: &user.User{
			ID:   userID.String(),
			Name: "Current Authority User",
			Role: permission.RoleUser,
		}},
		orgs: &fakeHumanOrganizationReader{
			assignment: &organization.UserOrganizationAssignment{
				UserID:                              userID,
				EffectiveOrganizationID:             orgID,
				EffectiveOrganizationClassification: organization.ClassificationNormal,
				Role:                                organization.OrganizationRoleMember,
				MappingOutcome:                      organization.MappingOutcomeExactlyOne,
				Evaluation: organization.AssignmentEvaluation{
					AuthoritativeEvaluatedAt: evaluatedAt,
					SourceConfigVersion:      "authority-config-v1",
					MatchedCount:             1,
				},
			},
			normal: &organization.NormalOrganization{
				Organization: organization.Organization{
					ID:             orgID,
					Classification: organization.ClassificationNormal,
					DisplayName:    "Current Authority Organization",
					CanonicalName:  "current-authority.organization",
					CreatedAt:      evaluatedAt.Add(-time.Hour),
					UpdatedAt:      evaluatedAt,
				},
				CorporateMappingKey: "corp:current-authority",
				TimeZone:            "Asia/Shanghai",
			},
		},
	}
}

func (f *humanExecutionContextFixture) constructor(t *testing.T) *HumanExecutionContextConstructor {
	t.Helper()
	constructor, err := newHumanExecutionContextConstructor(f.users, f.orgs)
	if err != nil {
		t.Fatal(err)
	}
	return constructor
}

func (f *humanExecutionContextFixture) setLegacyRole(role permission.Role) {
	requester := auth.RequesterFromContext(f.ctx)
	f.ctx = permission.UserSourceContext(context.Background(), f.userID.String(), role, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: f.sessionID.String()})
	if requester != nil {
		f.ctx = auth.WithRequester(f.ctx, *requester)
	}
}

func TestHumanExecutionContextAcceptedOrdinaryRoles(t *testing.T) {
	for _, test := range []struct {
		name       string
		globalRole permission.Role
		orgRole    organization.OrganizationRole
	}{
		{name: "user member", globalRole: permission.RoleUser, orgRole: organization.OrganizationRoleMember},
		{name: "user Organization admin", globalRole: permission.RoleUser, orgRole: organization.OrganizationRoleAdmin},
		{name: "global admin remains ordinary member", globalRole: permission.RoleAdmin, orgRole: organization.OrganizationRoleMember},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHumanExecutionContextFixture(t)
			fixture.users.user.Role = test.globalRole
			fixture.setLegacyRole(test.globalRole)
			fixture.orgs.assignment.Role = test.orgRole
			got, err := fixture.constructor(t).Construct(fixture.ctx)
			if err != nil || !got.Valid() {
				t.Fatalf("Construct = (%#v, %v), want valid", got, err)
			}
			if got.PrincipalKind() != PrincipalKindHuman || got.PrincipalID() != fixture.userID.String() ||
				got.ActualActorID() != fixture.userID.String() || got.AuthorityMode() != AuthorityModeOrganizationScoped {
				t.Fatalf("unexpected ExecutionContext: %#v", got)
			}
			if source := got.AuthenticationSource(); source == nil || source.Type() != permission.SourceTypeAuthProvider.String() || source.ID() != fixture.sessionID.String() {
				t.Fatalf("AuthenticationSource = %#v", source)
			}
			if privileges := got.Privileges(); privileges == nil || privileges.OrganizationRole() != test.orgRole || privileges.PlatformAdmin() {
				t.Fatalf("Privileges = %#v", privileges)
			}
			if id, present := got.EffectiveOrganizationID(); !present || id != fixture.orgID {
				t.Fatalf("EffectiveOrganizationID = (%s, %t)", id, present)
			}
			if fixture.users.calls != 1 || fixture.orgs.assignmentCalls != 1 || fixture.orgs.normalCalls != 1 {
				t.Fatalf("durable calls = user:%d assignment:%d Organization:%d", fixture.users.calls, fixture.orgs.assignmentCalls, fixture.orgs.normalCalls)
			}
			if fixture.users.lastID != fixture.userID.String() || fixture.orgs.assignmentID != fixture.userID || fixture.orgs.normalID != fixture.orgID {
				t.Fatal("constructor read a non-canonical durable identity")
			}
		})
	}
}

func TestHumanExecutionContextUsesCurrentTruthNotAuditProvenance(t *testing.T) {
	fixture := newHumanExecutionContextFixture(t)
	fixture.orgs.assignment.Evaluation.AuthoritativeEvaluatedAt = time.Time{}
	fixture.orgs.assignment.Evaluation.SourceConfigVersion = ""
	fixture.orgs.normal.DisplayName = ""
	fixture.orgs.normal.CanonicalName = ""
	fixture.orgs.normal.TimeZone = ""
	fixture.orgs.normal.CreatedAt = time.Time{}
	fixture.orgs.normal.UpdatedAt = time.Time{}
	got, err := fixture.constructor(t).Construct(fixture.ctx)
	if err != nil || !got.Valid() {
		t.Fatalf("non-authorizing audit metadata rejected current assignment truth: (%#v, %v)", got, err)
	}
}

func TestHumanExecutionContextFailsClosed(t *testing.T) {
	lookupFailure := errors.New("durable lookup failed")
	defaultID := uuid.MustParse(organization.DefaultOrganizationID)
	tests := []struct {
		name   string
		mutate func(*humanExecutionContextFixture)
	}{
		{name: "missing Requester", mutate: func(f *humanExecutionContextFixture) { f.ctx = context.Background() }},
		{name: "Requester without legacy metadata", mutate: func(f *humanExecutionContextFixture) {
			f.ctx = auth.WithRequester(context.Background(), *auth.RequesterFromContext(f.ctx))
		}},
		{name: "legacy Session mismatch", mutate: func(f *humanExecutionContextFixture) {
			requester := auth.RequesterFromContext(f.ctx)
			f.ctx = permission.UserSourceContext(context.Background(), f.userID.String(), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()})
			f.ctx = auth.WithRequester(f.ctx, *requester)
		}},
		{name: "non-human legacy source", mutate: func(f *humanExecutionContextFixture) {
			requester := auth.RequesterFromContext(f.ctx)
			f.ctx = permission.UserSourceContext(context.Background(), f.userID.String(), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: f.sessionID.String()})
			f.ctx = auth.WithRequester(f.ctx, *requester)
		}},
		{name: "missing User", mutate: func(f *humanExecutionContextFixture) { f.users.user = nil; f.users.err = sql.ErrNoRows }},
		{name: "User lookup failure", mutate: func(f *humanExecutionContextFixture) { f.users.err = lookupFailure }},
		{name: "User identity mismatch", mutate: func(f *humanExecutionContextFixture) { f.users.user.ID = uuid.NewString() }},
		{name: "invalid User role", mutate: func(f *humanExecutionContextFixture) { f.users.user.Role = permission.RoleUnknown }},
		{name: "legacy User role mismatch", mutate: func(f *humanExecutionContextFixture) { f.users.user.Role = permission.RoleAdmin }},
		{name: "missing assignment", mutate: func(f *humanExecutionContextFixture) {
			f.orgs.assignment = nil
			f.orgs.assignmentErr = organization.ErrUserAssignmentNotFound
		}},
		{name: "assignment lookup failure", mutate: func(f *humanExecutionContextFixture) { f.orgs.assignmentErr = lookupFailure }},
		{name: "assignment User mismatch", mutate: func(f *humanExecutionContextFixture) { f.orgs.assignment.UserID = uuid.New() }},
		{name: "ZERO mapping", mutate: func(f *humanExecutionContextFixture) {
			f.orgs.assignment.MappingOutcome = organization.MappingOutcomeZero
			f.orgs.assignment.EffectiveOrganizationID = defaultID
			f.orgs.assignment.EffectiveOrganizationClassification = organization.ClassificationDefault
			f.orgs.assignment.Role = organization.OrganizationRoleNone
			f.orgs.assignment.Evaluation.MatchedCount = 0
		}},
		{name: "MULTIPLE mapping", mutate: func(f *humanExecutionContextFixture) {
			f.orgs.assignment.MappingOutcome = organization.MappingOutcomeMultiple
			f.orgs.assignment.EffectiveOrganizationID = defaultID
			f.orgs.assignment.EffectiveOrganizationClassification = organization.ClassificationDefault
			f.orgs.assignment.Role = organization.OrganizationRoleNone
			f.orgs.assignment.Evaluation.MatchedCount = 2
		}},
		{name: "matched-count contradiction", mutate: func(f *humanExecutionContextFixture) { f.orgs.assignment.Evaluation.MatchedCount = 0 }},
		{name: "Default effective Organization", mutate: func(f *humanExecutionContextFixture) { f.orgs.assignment.EffectiveOrganizationID = defaultID }},
		{name: "NONE ordinary role", mutate: func(f *humanExecutionContextFixture) { f.orgs.assignment.Role = organization.OrganizationRoleNone }},
		{name: "missing NormalOrganization", mutate: func(f *humanExecutionContextFixture) {
			f.orgs.normal = nil
			f.orgs.normalErr = organization.ErrNotFound
		}},
		{name: "NormalOrganization lookup failure", mutate: func(f *humanExecutionContextFixture) { f.orgs.normalErr = lookupFailure }},
		{name: "Organization identity mismatch", mutate: func(f *humanExecutionContextFixture) { f.orgs.normal.ID = uuid.New() }},
		{name: "Organization classification mismatch", mutate: func(f *humanExecutionContextFixture) {
			f.orgs.normal.Classification = organization.ClassificationDefault
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHumanExecutionContextFixture(t)
			test.mutate(fixture)
			got, err := fixture.constructor(t).Construct(fixture.ctx)
			if !errors.Is(err, ErrHumanExecutionContextUnavailable) || got.Valid() {
				t.Fatalf("Construct = (%#v, %v), want unavailable", got, err)
			}
		})
	}
}

func TestHumanExecutionContextReconstructsAtEachAdmission(t *testing.T) {
	fixture := newHumanExecutionContextFixture(t)
	constructor := fixture.constructor(t)
	first, err := constructor.Construct(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	firstID, _ := first.EffectiveOrganizationID()

	secondID := uuid.MustParse("037159a2-0061-4570-976d-9313352c70f5")
	fixture.orgs.assignment.EffectiveOrganizationID = secondID
	fixture.orgs.normal.ID = secondID
	second, err := constructor.Construct(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	gotSecondID, _ := second.EffectiveOrganizationID()
	gotFirstID, _ := first.EffectiveOrganizationID()
	if firstID != fixture.orgID || gotFirstID != fixture.orgID || gotSecondID != secondID {
		t.Fatalf("request-admission values = first %s/%s second %s", firstID, gotFirstID, gotSecondID)
	}
	if fixture.users.calls != 2 || fixture.orgs.assignmentCalls != 2 || fixture.orgs.normalCalls != 2 {
		t.Fatalf("durable calls = user:%d assignment:%d Organization:%d, want two each", fixture.users.calls, fixture.orgs.assignmentCalls, fixture.orgs.normalCalls)
	}
}

func TestHumanExecutionContextConstructorValidation(t *testing.T) {
	fixture := newHumanExecutionContextFixture(t)
	var nilUsers *fakeHumanUserReader
	var nilOrganizations *fakeHumanOrganizationReader
	for _, test := range []struct {
		users humanExecutionContextUserReader
		orgs  humanExecutionContextOrganizationReader
	}{
		{users: nil, orgs: fixture.orgs},
		{users: nilUsers, orgs: fixture.orgs},
		{users: fixture.users, orgs: nil},
		{users: fixture.users, orgs: nilOrganizations},
	} {
		constructor, err := newHumanExecutionContextConstructor(test.users, test.orgs)
		if !errors.Is(err, ErrInvalidHumanExecutionContextConstructor) || constructor != nil {
			t.Fatalf("constructor = (%#v, %v), want invalid", constructor, err)
		}
	}
	var constructor *HumanExecutionContextConstructor
	if got, err := constructor.Construct(fixture.ctx); !errors.Is(err, ErrInvalidHumanExecutionContextConstructor) || got.Valid() {
		t.Fatalf("nil constructor Construct = (%#v, %v)", got, err)
	}
}
