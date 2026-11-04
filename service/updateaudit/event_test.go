package updateaudit

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRejectUnsafeEventBeforeStorage(t *testing.T) {
	e := Event{EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorKind: "unknown", AuthoritySource: "unknown", AuthorityRole: "unknown", OrganizationRole: "unknown", Outcome: "denied", Reason: "authority_denied", OccurredAt: time.Now()}
	require.ErrorIs(t, Append(context.Background(), nil, e), ErrUnavailable)
	for _, mutate := range []func(*Event){
		func(e *Event) { e.ActorKind = "SYNTHETIC_TOKEN" }, func(e *Event) { e.AuthorityRole = "SYNTHETIC_DESTINATION" }, func(e *Event) { e.Reason = "SYNTHETIC_SQL_ERROR" }, func(e *Event) { e.Outcome = "success" }, func(e *Event) { e.RequestedFields = 16 }, func(e *Event) { e.ServiceID = uuid.New() }, func(e *Event) { e.Outcome = "committed" }, func(e *Event) { e.ActorID = uuid.New() }, func(e *Event) { e.RequestID = uuid.Nil },
	} {
		x := e
		mutate(&x)
		require.ErrorIs(t, Append(context.Background(), nil, x), ErrInvalid)
	}
}
