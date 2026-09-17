package override

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
)

func TestOrganizationScope(t *testing.T) {
	scope, err := organizationScope(nil)
	require.NoError(t, err)
	require.False(t, scope.Valid)
	id := uuid.New()
	scope, err = organizationScope(&id)
	require.NoError(t, err)
	require.True(t, scope.Valid)
	require.Equal(t, id, scope.UUID)
	_, err = organizationScope(&uuid.Nil)
	require.Error(t, err)
}

func TestUserOverrideZeroOrganizationFailsClosed(t *testing.T) {
	s := new(Store) // Invalid authority must never reach a database.
	ctx := permission.SystemContext(context.Background(), "Smoketest")
	o := &UserOverride{ID: uuid.NewString(), Target: assignment.ScheduleTarget(uuid.NewString()),
		AddUserID: uuid.NewString(), Start: time.Now(), End: time.Now().Add(time.Hour)}
	checks := map[string]func() error{
		"read":   func() error { _, err := s.FindOneUserOverrideTxScoped(ctx, nil, o.ID, false, &uuid.Nil); return err },
		"search": func() error { _, err := s.SearchScoped(ctx, nil, nil, &uuid.Nil); return err },
		"create": func() error { _, err := s.CreateUserOverrideTxScoped(ctx, nil, o, &uuid.Nil); return err },
		"update": func() error { return s.UpdateUserOverrideTxScoped(ctx, nil, o, &uuid.Nil) },
		"delete": func() error { return s.DeleteUserOverrideTxScoped(ctx, nil, []string{o.ID}, &uuid.Nil) },
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			require.EqualError(t, check(), "invalid value for 'OrganizationID': must be specified")
		})
	}
}
