package calsub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth/authtoken"
	"github.com/target/goalert/config"
	"github.com/target/goalert/permission"
)

func TestCalendarProductPolicyBeforeDatabase(t *testing.T) {
	// A nil database/keyring makes any lookup, write, or signing attempt fail.
	s := new(Store)
	userID := uuid.NewString()
	ctx := permission.UserContext(context.Background(), userID, permission.RoleUser)
	for _, id := range []string{uuid.NewString(), uuid.NewString(), "malformed"} {
		sub, err := s.FindOne(ctx, id)
		require.Nil(t, sub)
		require.EqualError(t, err, "disabled by administrator")
		sub, err = s.FindOneForUpdate(ctx, nil, id)
		require.Nil(t, sub)
		require.EqualError(t, err, "disabled by administrator")
	}
	subs, err := s.FindAllByUser(ctx, userID)
	require.Nil(t, subs)
	require.EqualError(t, err, "disabled by administrator")
	for _, owner := range []string{userID, uuid.NewString()} {
		err = s.UpdateTx(ctx, nil, &Subscription{ID: uuid.NewString(), UserID: owner})
		require.EqualError(t, err, "disabled by administrator")
	}
	sub, err := s.CreateTx(ctx, nil, &Subscription{UserID: userID, ScheduleID: uuid.NewString()})
	require.Nil(t, sub, "no row or token may be issued")
	require.EqualError(t, err, "disabled by administrator")
	authorized, err := s.Authorize(context.Background(), authtoken.Token{Type: authtoken.TypeCalSub, ID: uuid.New()})
	require.True(t, permission.IsPermissionError(err))
	require.Nil(t, permission.Source(authorized))
}

func TestCalendarProductPolicyRenderDefense(t *testing.T) {
	ctx := permission.UserSourceContext(config.Config{}.Context(context.Background()), uuid.NewString(), permission.RoleUser, &permission.SourceInfo{
		Type: permission.SourceTypeCalendarSubscription,
		ID:   uuid.NewString(),
	})
	for _, accept := range []string{"application/json", "text/calendar"} {
		req := httptest.NewRequest("GET", "/api/v2/calendar", nil).WithContext(ctx)
		req.Header.Set("Accept", accept)
		w := httptest.NewRecorder()
		new(Store).ServeICalData(w, req)
		require.Equal(t, http.StatusForbidden, w.Code)
		require.Equal(t, "Forbidden\n", w.Body.String())
	}
}
