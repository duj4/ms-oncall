package executioncontext

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

type fakeHumanExecutionContextReader struct {
	value  *organization.CurrentUserOrganization
	err    error
	calls  int
	lastID uuid.UUID
}

func (r *fakeHumanExecutionContextReader) FindCurrentUserOrganization(_ context.Context, id uuid.UUID) (*organization.CurrentUserOrganization, error) {
	r.calls++
	r.lastID = id
	if r.value == nil {
		return nil, r.err
	}
	value := *r.value
	return &value, r.err
}

type humanExecutionContextFixture struct {
	sessionID uuid.UUID
	userID    uuid.UUID
	orgID     uuid.UUID
	ctx       context.Context
	reader    *fakeHumanExecutionContextReader
}

func newHumanExecutionContextFixture(t *testing.T) *humanExecutionContextFixture {
	t.Helper()
	sessionID := uuid.MustParse("5ad72c4f-92ed-4e42-b5a3-11359f6b5ac2")
	userID := uuid.MustParse("57accb9a-2985-48c7-8829-fac89c747a22")
	orgID := uuid.MustParse("70ca7d8d-6f35-45e8-9109-796b455d0e7b")
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
		reader: &fakeHumanExecutionContextReader{value: &organization.CurrentUserOrganization{
			UserID:         userID,
			UserRole:       permission.RoleUser,
			OrganizationID: orgID,
			Role:           organization.OrganizationRoleMember,
		}},
	}
}

func (f *humanExecutionContextFixture) constructor(t *testing.T) *HumanExecutionContextConstructor {
	t.Helper()
	constructor, err := newHumanExecutionContextConstructor(f.reader)
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

func TestHumanExecutionContextAcceptedOrdinaryRolesWithOneObservation(t *testing.T) {
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
			fixture.reader.value.UserRole = test.globalRole
			fixture.setLegacyRole(test.globalRole)
			fixture.reader.value.Role = test.orgRole
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
			if fixture.reader.calls != 1 || fixture.reader.lastID != fixture.userID {
				t.Fatalf("current-local observations = %d for %s, want exactly one for authenticated User", fixture.reader.calls, fixture.reader.lastID)
			}
		})
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
		{name: "no operational current row", mutate: func(f *humanExecutionContextFixture) {
			f.reader.value = nil
			f.reader.err = organization.ErrNotFound
		}},
		{name: "current-local lookup failure", mutate: func(f *humanExecutionContextFixture) { f.reader.err = lookupFailure }},
		{name: "User identity mismatch", mutate: func(f *humanExecutionContextFixture) { f.reader.value.UserID = uuid.New() }},
		{name: "invalid User role", mutate: func(f *humanExecutionContextFixture) { f.reader.value.UserRole = permission.RoleUnknown }},
		{name: "legacy User role mismatch", mutate: func(f *humanExecutionContextFixture) { f.reader.value.UserRole = permission.RoleAdmin }},
		{name: "nil effective Organization", mutate: func(f *humanExecutionContextFixture) { f.reader.value.OrganizationID = uuid.Nil }},
		{name: "Default effective Organization", mutate: func(f *humanExecutionContextFixture) { f.reader.value.OrganizationID = defaultID }},
		{name: "NONE ordinary role", mutate: func(f *humanExecutionContextFixture) { f.reader.value.Role = organization.OrganizationRoleNone }},
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
	fixture.reader.value.OrganizationID = secondID
	second, err := constructor.Construct(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	gotSecondID, _ := second.EffectiveOrganizationID()
	gotFirstID, _ := first.EffectiveOrganizationID()
	if firstID != fixture.orgID || gotFirstID != fixture.orgID || gotSecondID != secondID {
		t.Fatalf("request-admission values = first %s/%s second %s", firstID, gotFirstID, gotSecondID)
	}
	if fixture.reader.calls != 2 {
		t.Fatalf("current-local observations = %d, want two", fixture.reader.calls)
	}
}

func TestHumanExecutionContextConstructorValidation(t *testing.T) {
	fixture := newHumanExecutionContextFixture(t)
	var nilReader *fakeHumanExecutionContextReader
	for _, reader := range []humanExecutionContextReader{nil, nilReader} {
		constructor, err := newHumanExecutionContextConstructor(reader)
		if !errors.Is(err, ErrInvalidHumanExecutionContextConstructor) || constructor != nil {
			t.Fatalf("constructor = (%#v, %v), want invalid", constructor, err)
		}
	}
	var constructor *HumanExecutionContextConstructor
	if got, err := constructor.Construct(fixture.ctx); !errors.Is(err, ErrInvalidHumanExecutionContextConstructor) || got.Valid() {
		t.Fatalf("nil constructor Construct = (%#v, %v)", got, err)
	}
}
