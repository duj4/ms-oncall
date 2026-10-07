package label

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestOrganizationScopeValidation(t *testing.T) {
	// The accepted PR #29 scope contract remains intact in dormant code.
	scope, err := organizationScope(nil)
	require.NoError(t, err)
	require.False(t, scope.Valid)
	zero := uuid.Nil
	_, err = organizationScope(&zero)
	require.EqualError(t, err, "invalid value for 'OrganizationID': must be specified")
	id := uuid.New()
	scope, err = organizationScope(&id)
	require.NoError(t, err)
	require.True(t, scope.Valid)
	require.Equal(t, id, scope.UUID)
}
