package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestFindCurrentUserSessionFailsClosedWithoutCanonicalStore(t *testing.T) {
	validID := uuid.MustParse("57f3b9f8-661f-45a1-885d-696ae52fc49d")
	for _, test := range []struct {
		name      string
		handler   *Handler
		sessionID uuid.UUID
	}{
		{name: "nil Handler", sessionID: validID},
		{name: "zero Handler", handler: &Handler{}, sessionID: validID},
		{name: "nil session identity", handler: &Handler{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			session, err := test.handler.FindCurrentUserSession(context.Background(), test.sessionID)
			if session != nil || !errors.Is(err, ErrCurrentUserSessionNotFound) {
				t.Fatalf("FindCurrentUserSession = (%#v, %v), want nil and ErrCurrentUserSessionNotFound", session, err)
			}
		})
	}
}
