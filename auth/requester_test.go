package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRequesterContract(t *testing.T) {
	userID := uuid.MustParse("66cbfb6a-f4c6-43f7-9c6a-b7155f657ecd")
	sessionID := uuid.MustParse("e6b334d4-f366-4ad9-8485-1d97b66360b1")

	requester, err := NewRequester(userID.String(), sessionID.String())
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	if !requester.Valid() || requester.UserID() != userID || requester.SessionID() != sessionID {
		t.Fatalf("Requester = (%t, %s, %s), want valid canonical identities", requester.Valid(), requester.UserID(), requester.SessionID())
	}

	for _, test := range []struct {
		name      string
		userID    string
		sessionID string
	}{
		{name: "empty User", sessionID: sessionID.String()},
		{name: "malformed User", userID: "not-a-user", sessionID: sessionID.String()},
		{name: "zero User", userID: uuid.Nil.String(), sessionID: sessionID.String()},
		{name: "non-canonical User", userID: strings.ToUpper(userID.String()), sessionID: sessionID.String()},
		{name: "empty Session", userID: userID.String()},
		{name: "malformed Session", userID: userID.String(), sessionID: "not-a-session"},
		{name: "zero Session", userID: userID.String(), sessionID: uuid.Nil.String()},
		{name: "non-canonical Session", userID: userID.String(), sessionID: strings.ToUpper(sessionID.String())},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := NewRequester(test.userID, test.sessionID)
			if !errors.Is(err, ErrInvalidRequester) {
				t.Fatalf("NewRequester error = %v, want ErrInvalidRequester", err)
			}
			if got.Valid() || got.UserID() != uuid.Nil || got.SessionID() != uuid.Nil {
				t.Fatal("invalid construction exposed Requester identity")
			}
		})
	}
}

func TestRequesterZeroAndNilAccessorsFailClosed(t *testing.T) {
	var nilRequester *Requester
	zero := Requester{}
	for name, requester := range map[string]*Requester{"nil": nilRequester, "zero": &zero} {
		t.Run(name, func(t *testing.T) {
			if requester.Valid() || requester.UserID() != uuid.Nil || requester.SessionID() != uuid.Nil {
				t.Fatal("nil or zero Requester exposed identity")
			}
		})
	}
	if RequesterFromContext(nil) != nil || WithRequester(nil, zero) != nil {
		t.Fatal("nil context exposed or installed a Requester")
	}
}

func TestRequesterContextRoundTripUsesDefensiveCopies(t *testing.T) {
	userID := uuid.MustParse("66cbfb6a-f4c6-43f7-9c6a-b7155f657ecd")
	sessionID := uuid.MustParse("e6b334d4-f366-4ad9-8485-1d97b66360b1")
	requester, err := NewRequester(userID.String(), sessionID.String())
	if err != nil {
		t.Fatal(err)
	}

	base := context.Background()
	if got := WithRequester(base, Requester{}); got != base || RequesterFromContext(got) != nil {
		t.Fatal("invalid Requester was installed")
	}
	ctx := WithRequester(base, requester)
	first := RequesterFromContext(ctx)
	if first == nil || first.UserID() != userID || first.SessionID() != sessionID {
		t.Fatalf("RequesterFromContext = %#v, want original identity", first)
	}

	returnedUserID := first.UserID()
	returnedUserID[0] ^= 0xff
	first.userID = uuid.New()
	first.sessionID = uuid.New()
	second := RequesterFromContext(ctx)
	if second == nil || second.UserID() != userID || second.SessionID() != sessionID {
		t.Fatal("mutating returned values changed the stored Requester")
	}
}
