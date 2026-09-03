package executioncontext

import (
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

var (
	testSessionGenerationBindingSessionID = uuid.MustParse("4b8263b5-d370-4b22-8782-e14161a55a5c")
	testSessionGenerationBindingUserID    = uuid.MustParse("25c89639-a943-42b1-9432-dfabd882d1b4")
)

func TestNewSessionGenerationBindingValid(t *testing.T) {
	binding, err := newSessionGenerationBinding(
		testSessionGenerationBindingSessionID,
		testSessionGenerationBindingUserID,
		7,
		11,
	)
	if err != nil {
		t.Fatalf("newSessionGenerationBinding returned error: %v", err)
	}
	if !binding.Valid() {
		t.Fatal("valid construction returned an invalid binding")
	}

	if got, present := binding.SessionID(); !present || got != testSessionGenerationBindingSessionID {
		t.Fatalf("SessionID = (%s, %t), want (%s, true)", got, present, testSessionGenerationBindingSessionID)
	}
	if got, present := binding.UserID(); !present || got != testSessionGenerationBindingUserID {
		t.Fatalf("UserID = (%s, %t), want (%s, true)", got, present, testSessionGenerationBindingUserID)
	}
	if got, present := binding.AssignmentGeneration(); !present || got != 7 {
		t.Fatalf("AssignmentGeneration = (%d, %t), want (7, true)", got, present)
	}
	if got, present := binding.HumanSecurityGeneration(); !present || got != 11 {
		t.Fatalf("HumanSecurityGeneration = (%d, %t), want (11, true)", got, present)
	}
}

func TestSessionGenerationBindingIsImmutableThroughInputsAndAccessors(t *testing.T) {
	sessionID := testSessionGenerationBindingSessionID
	userID := testSessionGenerationBindingUserID
	binding, err := newSessionGenerationBinding(sessionID, userID, 7, 11)
	if err != nil {
		t.Fatalf("newSessionGenerationBinding returned error: %v", err)
	}

	sessionID[0]++
	userID[0]++
	returnedSessionID, _ := binding.SessionID()
	returnedUserID, _ := binding.UserID()
	returnedSessionID[0]++
	returnedUserID[0]++

	if got, present := binding.SessionID(); !present || got != testSessionGenerationBindingSessionID {
		t.Fatalf("SessionID changed through copied input or result: (%s, %t)", got, present)
	}
	if got, present := binding.UserID(); !present || got != testSessionGenerationBindingUserID {
		t.Fatalf("UserID changed through copied input or result: (%s, %t)", got, present)
	}
}

func TestSessionGenerationBindingZeroAndNilFailClosed(t *testing.T) {
	tests := map[string]*SessionGenerationBinding{
		"nil":  nil,
		"zero": {},
	}
	current := validSessionGenerationCurrentState()

	for name, binding := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("nil or zero binding panicked: %v", recovered)
				}
			}()

			if binding.Valid() {
				t.Fatal("nil or zero binding is valid")
			}
			if got, present := binding.SessionID(); present || got != uuid.Nil {
				t.Fatalf("SessionID = (%s, %t), want absent", got, present)
			}
			if got, present := binding.UserID(); present || got != uuid.Nil {
				t.Fatalf("UserID = (%s, %t), want absent", got, present)
			}
			if got, present := binding.AssignmentGeneration(); present || got != 0 {
				t.Fatalf("AssignmentGeneration = (%d, %t), want absent", got, present)
			}
			if got, present := binding.HumanSecurityGeneration(); present || got != 0 {
				t.Fatalf("HumanSecurityGeneration = (%d, %t), want absent", got, present)
			}
			if binding.CurrentAgainst(current) {
				t.Fatal("nil or zero binding is current")
			}
		})
	}
}

func TestNewSessionGenerationBindingRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name                    string
		sessionID               uuid.UUID
		userID                  uuid.UUID
		assignmentGeneration    int64
		humanSecurityGeneration int64
	}{
		{
			name:                    "zero session identity",
			userID:                  testSessionGenerationBindingUserID,
			assignmentGeneration:    7,
			humanSecurityGeneration: 11,
		},
		{
			name:                    "zero User identity",
			sessionID:               testSessionGenerationBindingSessionID,
			assignmentGeneration:    7,
			humanSecurityGeneration: 11,
		},
		{
			name:                    "zero assignment generation",
			sessionID:               testSessionGenerationBindingSessionID,
			userID:                  testSessionGenerationBindingUserID,
			humanSecurityGeneration: 11,
		},
		{
			name:                    "negative assignment generation",
			sessionID:               testSessionGenerationBindingSessionID,
			userID:                  testSessionGenerationBindingUserID,
			assignmentGeneration:    -1,
			humanSecurityGeneration: 11,
		},
		{
			name:                 "zero human-security generation",
			sessionID:            testSessionGenerationBindingSessionID,
			userID:               testSessionGenerationBindingUserID,
			assignmentGeneration: 7,
		},
		{
			name:                    "negative human-security generation",
			sessionID:               testSessionGenerationBindingSessionID,
			userID:                  testSessionGenerationBindingUserID,
			assignmentGeneration:    7,
			humanSecurityGeneration: -1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binding, err := newSessionGenerationBinding(
				test.sessionID,
				test.userID,
				test.assignmentGeneration,
				test.humanSecurityGeneration,
			)
			if err == nil {
				t.Fatal("invalid construction returned no error")
			}
			if binding.Valid() {
				t.Fatal("invalid construction returned a valid binding")
			}
			if binding != (SessionGenerationBinding{}) {
				t.Fatalf("invalid construction returned non-zero binding: %#v", binding)
			}
			if binding.CurrentAgainst(validSessionGenerationCurrentState()) {
				t.Fatal("rejected construction returned current evidence")
			}
		})
	}
}

func TestSessionGenerationBindingCurrentAgainst(t *testing.T) {
	binding, err := newSessionGenerationBinding(
		testSessionGenerationBindingSessionID,
		testSessionGenerationBindingUserID,
		7,
		11,
	)
	if err != nil {
		t.Fatalf("newSessionGenerationBinding returned error: %v", err)
	}

	differentUserID := uuid.MustParse("71844883-14cc-420f-8600-506229927d4a")
	tests := []struct {
		name    string
		mutate  func(*SessionGenerationCurrentState)
		current bool
	}{
		{name: "exact positive ACTIVE match", current: true},
		{name: "zero current User identity", mutate: func(state *SessionGenerationCurrentState) {
			state.UserID = uuid.Nil
		}},
		{name: "different current User identity", mutate: func(state *SessionGenerationCurrentState) {
			state.UserID = differentUserID
		}},
		{name: "zero assignment state", mutate: func(state *SessionGenerationCurrentState) {
			state.AssignmentState = ""
		}},
		{name: "unknown assignment state", mutate: func(state *SessionGenerationCurrentState) {
			state.AssignmentState = organization.AssignmentState("UNKNOWN")
		}},
		{name: "TRANSITIONING assignment", mutate: func(state *SessionGenerationCurrentState) {
			state.AssignmentState = organization.AssignmentStateTransitioning
		}},
		{name: "zero assignment generation", mutate: func(state *SessionGenerationCurrentState) {
			state.AssignmentGeneration = 0
		}},
		{name: "negative assignment generation", mutate: func(state *SessionGenerationCurrentState) {
			state.AssignmentGeneration = -1
		}},
		{name: "lower assignment generation", mutate: func(state *SessionGenerationCurrentState) {
			state.AssignmentGeneration = 6
		}},
		{name: "higher assignment generation", mutate: func(state *SessionGenerationCurrentState) {
			state.AssignmentGeneration = 8
		}},
		{name: "zero human-security generation", mutate: func(state *SessionGenerationCurrentState) {
			state.HumanSecurityGeneration = 0
		}},
		{name: "negative human-security generation", mutate: func(state *SessionGenerationCurrentState) {
			state.HumanSecurityGeneration = -1
		}},
		{name: "lower human-security generation", mutate: func(state *SessionGenerationCurrentState) {
			state.HumanSecurityGeneration = 10
		}},
		{name: "higher human-security generation", mutate: func(state *SessionGenerationCurrentState) {
			state.HumanSecurityGeneration = 12
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("CurrentAgainst panicked: %v", recovered)
				}
			}()

			current := validSessionGenerationCurrentState()
			if test.mutate != nil {
				test.mutate(&current)
			}
			if got := binding.CurrentAgainst(current); got != test.current {
				t.Fatalf("CurrentAgainst(%+v) = %t, want %t", current, got, test.current)
			}
		})
	}
}

func validSessionGenerationCurrentState() SessionGenerationCurrentState {
	return SessionGenerationCurrentState{
		UserID:                  testSessionGenerationBindingUserID,
		AssignmentState:         organization.AssignmentStateActive,
		AssignmentGeneration:    7,
		HumanSecurityGeneration: 11,
	}
}
