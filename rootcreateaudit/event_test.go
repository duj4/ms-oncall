package rootcreateaudit

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

func TestCreateEventIdentityAndOutcomeContract(t *testing.T) {
	e := Event{EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorID: uuid.New(), HomeOrganizationID: uuid.MustParse(organization.DefaultOrganizationID), OrganizationRole: "NONE", RootType: "service", RootID: uuid.New(), TargetOrganizationID: uuid.New(), Outcome: "committed", Reason: "created", OccurredAt: time.Now()}
	if !e.valid() {
		t.Fatal("legal Default PA event rejected")
	}
	for name, mutate := range map[string]func(*Event){
		"NONE with Normal Home":    func(e *Event) { e.HomeOrganizationID = uuid.New() },
		"Default with member role": func(e *Event) { e.OrganizationRole = "ORG_MEMBER" },
		"Default Target":           func(e *Event) { e.TargetOrganizationID = uuid.MustParse(organization.DefaultOrganizationID) },
		"success without Root":     func(e *Event) { e.RootID = uuid.Nil },
		"unknown as success":       func(e *Event) { e.Outcome = "commit_unknown" },
		"unapproved Root":          func(e *Event) { e.RootType = "alert" },
		"missing actor":            func(e *Event) { e.ActorID = uuid.Nil },
	} {
		t.Run(name, func(t *testing.T) {
			v := e
			mutate(&v)
			if v.valid() {
				t.Fatal("invalid event accepted")
			}
		})
	}
	e.Outcome, e.Reason = "commit_unknown", "commit_unconfirmed"
	if !e.valid() {
		t.Fatal("uncertainty observation rejected")
	}
}
