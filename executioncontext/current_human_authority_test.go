package executioncontext

import (
	"context"
	"crypto/sha256"
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

type fakeCurrentHumanSessionReader struct {
	session *auth.CurrentUserSession
	err     error
	calls   int
}

func (r *fakeCurrentHumanSessionReader) FindCurrentUserSession(context.Context, uuid.UUID) (*auth.CurrentUserSession, error) {
	r.calls++
	if r.session == nil {
		return nil, r.err
	}
	value := *r.session
	return &value, r.err
}

type fakeCurrentHumanUserReader struct {
	user  *user.User
	err   error
	calls int
}

func (r *fakeCurrentHumanUserReader) FindOne(context.Context, string) (*user.User, error) {
	r.calls++
	if r.user == nil {
		return nil, r.err
	}
	value := *r.user
	return &value, r.err
}

type fakeCurrentHumanOrganizationReader struct {
	assignment      *organization.UserOrganizationAssignment
	assignmentErr   error
	normal          *organization.NormalOrganization
	normalErr       error
	assignmentCalls int
	normalCalls     int
}

func (r *fakeCurrentHumanOrganizationReader) FindUserOrganizationAssignment(context.Context, uuid.UUID) (*organization.UserOrganizationAssignment, error) {
	r.assignmentCalls++
	if r.assignment == nil {
		return nil, r.assignmentErr
	}
	value := *r.assignment
	if r.assignment.PendingTransferID != nil {
		pending := *r.assignment.PendingTransferID
		value.PendingTransferID = &pending
	}
	return &value, r.assignmentErr
}

func (r *fakeCurrentHumanOrganizationReader) FindNormalByID(context.Context, uuid.UUID) (*organization.NormalOrganization, error) {
	r.normalCalls++
	if r.normal == nil {
		return nil, r.normalErr
	}
	value := *r.normal
	return &value, r.normalErr
}

type currentHumanAuthorityFixture struct {
	sessionID uuid.UUID
	userID    uuid.UUID
	orgID     uuid.UUID
	ctx       context.Context
	sessions  *fakeCurrentHumanSessionReader
	users     *fakeCurrentHumanUserReader
	orgs      *fakeCurrentHumanOrganizationReader
}

func newCurrentHumanAuthorityFixture(t *testing.T) *currentHumanAuthorityFixture {
	t.Helper()
	sessionID := uuid.MustParse("5ad72c4f-92ed-4e42-b5a3-11359f6b5ac2")
	userID := uuid.MustParse("57accb9a-2985-48c7-8829-fac89c747a22")
	orgID := uuid.MustParse("70ca7d8d-6f35-45e8-9109-796b455d0e7b")
	evaluatedAt := time.Date(2026, time.September, 6, 2, 0, 0, 0, time.UTC)
	createdAt := evaluatedAt.Add(-time.Hour)

	ctx := permission.UserSourceContext(
		context.Background(),
		userID.String(),
		permission.RoleUser,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: sessionID.String()},
	)
	return &currentHumanAuthorityFixture{
		sessionID: sessionID,
		userID:    userID,
		orgID:     orgID,
		ctx:       ctx,
		sessions: &fakeCurrentHumanSessionReader{session: &auth.CurrentUserSession{
			ID:       sessionID,
			UserID:   userID,
			UserRole: permission.RoleUser,
		}},
		users: &fakeCurrentHumanUserReader{user: &user.User{
			ID:   userID.String(),
			Name: "Current Authority User",
			Role: permission.RoleUser,
		}},
		orgs: &fakeCurrentHumanOrganizationReader{
			assignment: &organization.UserOrganizationAssignment{
				UserID:                              userID,
				EffectiveOrganizationID:             orgID,
				EffectiveOrganizationClassification: organization.ClassificationNormal,
				State:                               organization.AssignmentStateActive,
				Role:                                organization.OrganizationRoleMember,
				AssignmentGeneration:                7,
				MappingOutcome:                      organization.MappingOutcomeExactlyOne,
				Evaluation: organization.AssignmentEvaluation{
					AuthoritativeEvaluatedAt: evaluatedAt,
					SourceConfigVersion:      "authority-config-v7",
					MatchedCount:             1,
					EvidenceDigest:           sha256.Sum256([]byte("current-authority-evidence")),
				},
			},
			normal: &organization.NormalOrganization{
				Organization: organization.Organization{
					ID:             orgID,
					Classification: organization.ClassificationNormal,
					DisplayName:    "Current Authority Organization",
					CanonicalName:  "current-authority.organization",
					Lifecycle:      organization.LifecycleActive,
					CreatedAt:      createdAt,
					UpdatedAt:      evaluatedAt,
				},
				CorporateMappingKey: "corp:current-authority",
				TimeZone:            "Asia/Shanghai",
			},
		},
	}
}

func (f *currentHumanAuthorityFixture) constructor(t *testing.T) *CurrentHumanAuthorityConstructor {
	t.Helper()
	constructor, err := newCurrentHumanAuthorityConstructor(f.sessions, f.users, f.orgs)
	if err != nil {
		t.Fatalf("newCurrentHumanAuthorityConstructor: %v", err)
	}
	return constructor
}

func TestCurrentHumanAuthorityAcceptedOrdinaryRoles(t *testing.T) {
	for _, test := range []struct {
		name       string
		globalRole permission.Role
		orgRole    organization.OrganizationRole
	}{
		{name: "legacy user as ORG_MEMBER", globalRole: permission.RoleUser, orgRole: organization.OrganizationRoleMember},
		{name: "legacy user as ORG_ADMIN", globalRole: permission.RoleUser, orgRole: organization.OrganizationRoleAdmin},
		{name: "legacy admin remains ordinary ORG_MEMBER", globalRole: permission.RoleAdmin, orgRole: organization.OrganizationRoleMember},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCurrentHumanAuthorityFixture(t)
			fixture.sessions.session.UserRole = test.globalRole
			fixture.users.user.Role = test.globalRole
			fixture.orgs.assignment.Role = test.orgRole
			result, err := fixture.constructor(t).Construct(fixture.ctx)
			if err != nil {
				t.Fatalf("Construct: %v", err)
			}
			if !result.Valid() {
				t.Fatal("CurrentHumanAuthority.Valid = false, want true")
			}

			typed := result.ExecutionContext()
			if typed == nil || !typed.Valid() || typed.PrincipalKind() != PrincipalKindHuman ||
				typed.PrincipalID() != fixture.userID.String() || typed.ActualActorID() != fixture.userID.String() ||
				typed.AuthorityMode() != AuthorityModeOrganizationScoped {
				t.Fatalf("unexpected typed ExecutionContext: %#v", typed)
			}
			source := typed.AuthenticationSource()
			if source == nil || source.Type() != permission.SourceTypeAuthProvider.String() || source.ID() != fixture.sessionID.String() {
				t.Fatalf("AuthenticationSource = %#v, want current AuthProvider session", source)
			}
			privileges := typed.Privileges()
			if privileges == nil || privileges.OrganizationRole() != test.orgRole || privileges.PlatformAdmin() {
				t.Fatalf("Privileges = %#v, want ordinary role %q without PlatformAdmin", privileges, test.orgRole)
			}
			if id, present := typed.EffectiveOrganizationID(); !present || id != fixture.orgID {
				t.Fatalf("EffectiveOrganizationID = (%s, %t), want (%s, true)", id, present, fixture.orgID)
			}
			if generation, present := typed.AssignmentGeneration(); !present || generation != 7 {
				t.Fatalf("AssignmentGeneration = (%d, %t), want (7, true)", generation, present)
			}
			if _, present := typed.PlatformAdminAssumptionID(); present {
				t.Fatal("ordinary authority unexpectedly carries PlatformAdmin assumption")
			}
			if !EligibleForOrganizationBusinessScope(typed, fixture.orgID) {
				t.Fatal("accepted current authority is incompatible with Organization policy scope")
			}

			observation := result.Observation()
			if observation == nil || !observation.Valid() || !observation.SessionCurrent() ||
				observation.SessionID() != fixture.sessionID || observation.UserID() != fixture.userID ||
				observation.GlobalUserRole() != test.globalRole || observation.AssignmentUserID() != fixture.userID ||
				observation.AssignmentState() != organization.AssignmentStateActive ||
				observation.MappingOutcome() != organization.MappingOutcomeExactlyOne ||
				observation.EffectiveOrganizationID() != fixture.orgID || observation.OrganizationRole() != test.orgRole ||
				observation.AssignmentGeneration() != 7 ||
				observation.OrganizationClassification() != organization.ClassificationNormal ||
				observation.OrganizationLifecycle() != organization.LifecycleActive {
				t.Fatalf("unexpected current-authority observation: %#v", observation)
			}
			if fixture.sessions.calls != 1 || fixture.users.calls != 1 || fixture.orgs.assignmentCalls != 1 || fixture.orgs.normalCalls != 1 {
				t.Fatalf("durable read calls = session:%d user:%d assignment:%d Organization:%d, want one each",
					fixture.sessions.calls, fixture.users.calls, fixture.orgs.assignmentCalls, fixture.orgs.normalCalls)
			}
		})
	}
}

func TestCurrentHumanAuthorityFailsClosed(t *testing.T) {
	lookupFailure := errors.New("durable lookup failed")
	defaultID := uuid.MustParse(organization.DefaultOrganizationID)
	pendingID := uuid.MustParse("2864cb0f-529e-4a79-ac24-b5d928f71d94")

	tests := []struct {
		name   string
		mutate func(*currentHumanAuthorityFixture)
	}{
		{name: "missing authentication source", mutate: func(f *currentHumanAuthorityFixture) { f.ctx = context.Background() }},
		{name: "non-human authentication source", mutate: func(f *currentHumanAuthorityFixture) {
			f.ctx = permission.UserSourceContext(context.Background(), f.userID.String(), permission.RoleUser,
				&permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: f.sessionID.String()})
		}},
		{name: "malformed session identity", mutate: func(f *currentHumanAuthorityFixture) {
			f.ctx = permission.UserSourceContext(context.Background(), f.userID.String(), permission.RoleUser,
				&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: "not-a-session"})
		}},
		{name: "malformed authenticated User identity", mutate: func(f *currentHumanAuthorityFixture) {
			f.ctx = permission.UserSourceContext(context.Background(), "not-a-user", permission.RoleUser,
				&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: f.sessionID.String()})
		}},
		{name: "missing or revoked session", mutate: func(f *currentHumanAuthorityFixture) {
			f.sessions.session = nil
			f.sessions.err = auth.ErrCurrentUserSessionNotFound
		}},
		{name: "session lookup failure", mutate: func(f *currentHumanAuthorityFixture) { f.sessions.err = lookupFailure }},
		{name: "nil session result", mutate: func(f *currentHumanAuthorityFixture) { f.sessions.session = nil }},
		{name: "session identity mismatch", mutate: func(f *currentHumanAuthorityFixture) { f.sessions.session.ID = uuid.New() }},
		{name: "session User mismatch", mutate: func(f *currentHumanAuthorityFixture) { f.sessions.session.UserID = uuid.New() }},
		{name: "missing User", mutate: func(f *currentHumanAuthorityFixture) { f.users.user = nil; f.users.err = sql.ErrNoRows }},
		{name: "User lookup failure", mutate: func(f *currentHumanAuthorityFixture) { f.users.err = lookupFailure }},
		{name: "nil User result", mutate: func(f *currentHumanAuthorityFixture) { f.users.user = nil }},
		{name: "malformed User", mutate: func(f *currentHumanAuthorityFixture) {
			f.users.user.Role = permission.RoleUnknown
			f.sessions.session.UserRole = permission.RoleUnknown
		}},
		{name: "User identity mismatch", mutate: func(f *currentHumanAuthorityFixture) { f.users.user.ID = uuid.NewString() }},
		{name: "session User role mismatch", mutate: func(f *currentHumanAuthorityFixture) { f.sessions.session.UserRole = permission.RoleAdmin }},
		{name: "missing assignment", mutate: func(f *currentHumanAuthorityFixture) {
			f.orgs.assignment = nil
			f.orgs.assignmentErr = organization.ErrUserAssignmentNotFound
		}},
		{name: "assignment lookup failure", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.assignmentErr = lookupFailure }},
		{name: "nil assignment result", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.assignment = nil }},
		{name: "assignment User mismatch", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.assignment.UserID = uuid.New() }},
		{name: "ZERO resolution", mutate: func(f *currentHumanAuthorityFixture) {
			f.orgs.assignment.MappingOutcome = organization.MappingOutcomeZero
			f.orgs.assignment.EffectiveOrganizationID = defaultID
			f.orgs.assignment.EffectiveOrganizationClassification = organization.ClassificationDefault
			f.orgs.assignment.Role = organization.OrganizationRoleNone
			f.orgs.assignment.Evaluation.MatchedCount = 0
		}},
		{name: "MULTIPLE resolution", mutate: func(f *currentHumanAuthorityFixture) {
			f.orgs.assignment.MappingOutcome = organization.MappingOutcomeMultiple
			f.orgs.assignment.EffectiveOrganizationID = defaultID
			f.orgs.assignment.EffectiveOrganizationClassification = organization.ClassificationDefault
			f.orgs.assignment.Role = organization.OrganizationRoleNone
			f.orgs.assignment.Evaluation.MatchedCount = 2
		}},
		{name: "TRANSITIONING assignment", mutate: func(f *currentHumanAuthorityFixture) {
			f.orgs.assignment.State = organization.AssignmentStateTransitioning
			f.orgs.assignment.PendingTransferID = &pendingID
		}},
		{name: "unknown assignment state", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.assignment.State = "UNKNOWN" }},
		{name: "Default Organization", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.assignment.EffectiveOrganizationID = defaultID }},
		{name: "missing effective Organization", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.assignment.EffectiveOrganizationID = uuid.Nil }},
		{name: "non-Normal assignment classification", mutate: func(f *currentHumanAuthorityFixture) {
			f.orgs.assignment.EffectiveOrganizationClassification = organization.ClassificationDefault
		}},
		{name: "NONE ordinary role", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.assignment.Role = organization.OrganizationRoleNone }},
		{name: "unknown ordinary role", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.assignment.Role = "OWNER" }},
		{name: "zero AssignmentGeneration", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.assignment.AssignmentGeneration = 0 }},
		{name: "negative AssignmentGeneration", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.assignment.AssignmentGeneration = -1 }},
		{name: "inconsistent resolver matched count", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.assignment.Evaluation.MatchedCount = 0 }},
		{name: "missing resolver evaluation time", mutate: func(f *currentHumanAuthorityFixture) {
			f.orgs.assignment.Evaluation.AuthoritativeEvaluatedAt = time.Time{}
		}},
		{name: "missing resolver source version", mutate: func(f *currentHumanAuthorityFixture) {
			f.orgs.assignment.Evaluation.SourceConfigVersion = ""
		}},
		{name: "missing resolver evidence digest", mutate: func(f *currentHumanAuthorityFixture) {
			f.orgs.assignment.Evaluation.EvidenceDigest = organization.EvidenceDigest{}
		}},
		{name: "ACTIVE assignment with pending transfer", mutate: func(f *currentHumanAuthorityFixture) {
			f.orgs.assignment.PendingTransferID = &pendingID
		}},
		{name: "missing NormalOrganization", mutate: func(f *currentHumanAuthorityFixture) {
			f.orgs.normal = nil
			f.orgs.normalErr = organization.ErrNotFound
		}},
		{name: "NormalOrganization lookup failure", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.normalErr = lookupFailure }},
		{name: "nil NormalOrganization result", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.normal = nil }},
		{name: "Organization identity mismatch", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.normal.ID = uuid.New() }},
		{name: "Default returned as NormalOrganization", mutate: func(f *currentHumanAuthorityFixture) {
			f.orgs.normal.ID = defaultID
			f.orgs.assignment.EffectiveOrganizationID = defaultID
		}},
		{name: "non-Normal Organization classification", mutate: func(f *currentHumanAuthorityFixture) {
			f.orgs.normal.Classification = organization.ClassificationDefault
		}},
		{name: "suspended Organization", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.normal.Lifecycle = organization.LifecycleSuspended }},
		{name: "retired Organization", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.normal.Lifecycle = organization.LifecycleRetired }},
		{name: "unknown Organization lifecycle", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.normal.Lifecycle = "UNKNOWN" }},
		{name: "invalid Organization time zone", mutate: func(f *currentHumanAuthorityFixture) { f.orgs.normal.TimeZone = "+08:00" }},
		{name: "invalid Organization audit state", mutate: func(f *currentHumanAuthorityFixture) {
			f.orgs.normal.UpdatedAt = f.orgs.normal.CreatedAt.Add(-time.Second)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCurrentHumanAuthorityFixture(t)
			test.mutate(fixture)
			result, err := fixture.constructor(t).Construct(fixture.ctx)
			if !errors.Is(err, ErrCurrentHumanAuthorityUnavailable) {
				t.Fatalf("Construct error = %v, want ErrCurrentHumanAuthorityUnavailable", err)
			}
			assertNoCurrentHumanAuthority(t, &result)
		})
	}

	t.Run("canceled operation context", func(t *testing.T) {
		fixture := newCurrentHumanAuthorityFixture(t)
		ctx, cancel := context.WithCancel(fixture.ctx)
		cancel()
		result, err := fixture.constructor(t).Construct(ctx)
		if !errors.Is(err, ErrCurrentHumanAuthorityUnavailable) || !errors.Is(err, context.Canceled) {
			t.Fatalf("Construct error = %v, want authority unavailable and context canceled", err)
		}
		assertNoCurrentHumanAuthority(t, &result)
	})
}

func TestCurrentHumanAuthorityConstructionReobservesCurrentState(t *testing.T) {
	fixture := newCurrentHumanAuthorityFixture(t)
	constructor := fixture.constructor(t)

	first, err := constructor.Construct(fixture.ctx)
	if err != nil {
		t.Fatalf("first Construct: %v", err)
	}
	if first.Observation().AssignmentGeneration() != 7 {
		t.Fatal("first construction did not observe generation 7")
	}

	fixture.orgs.assignment.State = organization.AssignmentStateTransitioning
	fixture.orgs.assignment.AssignmentGeneration = 8
	fixture.orgs.assignment.PendingTransferID = pointerTo(uuid.MustParse("7944898f-f83a-4876-900b-ef6ad41ed9fa"))
	second, err := constructor.Construct(fixture.ctx)
	if !errors.Is(err, ErrCurrentHumanAuthorityUnavailable) {
		t.Fatalf("second Construct error = %v, want fail-closed current TRANSITIONING state", err)
	}
	assertNoCurrentHumanAuthority(t, &second)
	if first.Observation().AssignmentGeneration() != 7 || first.Observation().AssignmentState() != organization.AssignmentStateActive {
		t.Fatal("prior operation-local observation was mutated by later durable state")
	}

	fixture.orgs.assignment.State = organization.AssignmentStateActive
	fixture.orgs.assignment.PendingTransferID = nil
	fixture.orgs.normal.Lifecycle = organization.LifecycleSuspended
	third, err := constructor.Construct(fixture.ctx)
	if !errors.Is(err, ErrCurrentHumanAuthorityUnavailable) {
		t.Fatalf("third Construct error = %v, want fail-closed current suspended Organization", err)
	}
	assertNoCurrentHumanAuthority(t, &third)

	fixture.orgs.normal.Lifecycle = organization.LifecycleActive
	fixture.sessions.session = nil
	fixture.sessions.err = auth.ErrCurrentUserSessionNotFound
	fourth, err := constructor.Construct(fixture.ctx)
	if !errors.Is(err, ErrCurrentHumanAuthorityUnavailable) {
		t.Fatalf("fourth Construct error = %v, want fail-closed current revoked session", err)
	}
	assertNoCurrentHumanAuthority(t, &fourth)

	fixture.sessions.session = &auth.CurrentUserSession{ID: fixture.sessionID, UserID: fixture.userID, UserRole: permission.RoleUser}
	fixture.sessions.err = nil
	fifth, err := constructor.Construct(fixture.ctx)
	if err != nil {
		t.Fatalf("fifth Construct: %v", err)
	}
	if fifth.Observation().AssignmentGeneration() != 8 {
		t.Fatalf("fifth generation = %d, want freshly observed 8", fifth.Observation().AssignmentGeneration())
	}
	if fixture.sessions.calls != 5 || fixture.users.calls != 4 || fixture.orgs.assignmentCalls != 4 || fixture.orgs.normalCalls != 3 {
		t.Fatalf("durable lookup counts = session:%d user:%d assignment:%d Organization:%d, want 5/4/4/3",
			fixture.sessions.calls, fixture.users.calls, fixture.orgs.assignmentCalls, fixture.orgs.normalCalls)
	}
}

func TestCurrentHumanAuthorityConstructorAndZeroValuesFailClosed(t *testing.T) {
	fixture := newCurrentHumanAuthorityFixture(t)
	var nilSessions *fakeCurrentHumanSessionReader
	var nilUsers *fakeCurrentHumanUserReader
	var nilOrganizations *fakeCurrentHumanOrganizationReader

	for _, test := range []struct {
		name     string
		sessions currentHumanSessionReader
		users    currentHumanUserReader
		orgs     currentHumanOrganizationReader
	}{
		{name: "nil sessions", users: fixture.users, orgs: fixture.orgs},
		{name: "typed nil sessions", sessions: nilSessions, users: fixture.users, orgs: fixture.orgs},
		{name: "nil users", sessions: fixture.sessions, orgs: fixture.orgs},
		{name: "typed nil users", sessions: fixture.sessions, users: nilUsers, orgs: fixture.orgs},
		{name: "nil Organizations", sessions: fixture.sessions, users: fixture.users},
		{name: "typed nil Organizations", sessions: fixture.sessions, users: fixture.users, orgs: nilOrganizations},
	} {
		t.Run(test.name, func(t *testing.T) {
			constructor, err := newCurrentHumanAuthorityConstructor(test.sessions, test.users, test.orgs)
			if !errors.Is(err, ErrInvalidCurrentHumanAuthorityConstructor) || constructor != nil {
				t.Fatalf("constructor, error = (%#v, %v), want nil and invalid-constructor error", constructor, err)
			}
		})
	}

	var nilConstructor *CurrentHumanAuthorityConstructor
	result, err := nilConstructor.Construct(fixture.ctx)
	if !errors.Is(err, ErrInvalidCurrentHumanAuthorityConstructor) {
		t.Fatalf("nil constructor error = %v, want ErrInvalidCurrentHumanAuthorityConstructor", err)
	}
	assertNoCurrentHumanAuthority(t, &result)

	zeroConstructor := &CurrentHumanAuthorityConstructor{}
	result, err = zeroConstructor.Construct(fixture.ctx)
	if !errors.Is(err, ErrInvalidCurrentHumanAuthorityConstructor) {
		t.Fatalf("zero constructor error = %v, want ErrInvalidCurrentHumanAuthorityConstructor", err)
	}
	assertNoCurrentHumanAuthority(t, &result)

	assertNoCurrentHumanAuthority(t, nil)
	zero := CurrentHumanAuthority{}
	assertNoCurrentHumanAuthority(t, &zero)
	var nilObservation *CurrentHumanAuthorityObservation
	assertZeroCurrentHumanAuthorityObservation(t, nilObservation)
	zeroObservation := CurrentHumanAuthorityObservation{}
	assertZeroCurrentHumanAuthorityObservation(t, &zeroObservation)
}

func TestCurrentHumanAuthorityReturnedEvidenceIsImmutableByCopy(t *testing.T) {
	fixture := newCurrentHumanAuthorityFixture(t)
	result, err := fixture.constructor(t).Construct(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}

	typed := result.ExecutionContext()
	observation := result.Observation()
	typed.valid = false
	observation.valid = false
	observation.assignmentGeneration = 99
	if !result.Valid() || !result.ExecutionContext().Valid() || !result.Observation().Valid() ||
		result.Observation().AssignmentGeneration() != 7 {
		t.Fatal("mutating returned copies changed the accepted result")
	}
}

func assertNoCurrentHumanAuthority(t *testing.T, value *CurrentHumanAuthority) {
	t.Helper()
	if value != nil && value.Valid() {
		t.Fatal("invalid CurrentHumanAuthority.Valid = true")
	}
	if value != nil && (value.ExecutionContext() != nil || value.Observation() != nil) {
		t.Fatal("invalid CurrentHumanAuthority exposed trusted evidence")
	}
}

func assertZeroCurrentHumanAuthorityObservation(t *testing.T, value *CurrentHumanAuthorityObservation) {
	t.Helper()
	if value.Valid() || value.SessionCurrent() || value.SessionID() != uuid.Nil || value.UserID() != uuid.Nil ||
		value.GlobalUserRole() != "" || value.AssignmentUserID() != uuid.Nil || value.AssignmentState() != "" ||
		value.MappingOutcome() != "" || value.EffectiveOrganizationID() != uuid.Nil || value.OrganizationRole() != "" ||
		value.AssignmentGeneration() != 0 || value.OrganizationClassification() != "" || value.OrganizationLifecycle() != "" {
		t.Fatal("nil or zero CurrentHumanAuthorityObservation exposed evidence")
	}
}
