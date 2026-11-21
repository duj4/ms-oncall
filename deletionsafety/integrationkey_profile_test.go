package deletionsafety

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestIntegrationKeyRootPreservesServiceAndHistory(t *testing.T) {
	credential := uuid.NewString() // synthetic authentication selector, never a plan ID
	key := obj(ResourceIntegrationKey, uuid.NewString())
	service, history := obj(ResourceService, uuid.NewString()), obj(ResourceAlertLog, "42")
	plan := mustPlan(t, inputFor([]Resource{key},
		dep(key, service, RelationshipIntegrationSource, Resource{}, Resource{}),
		dep(key, history, RelationshipIntegrationLog, Resource{}, Resource{})))
	require.True(t, plan.CanProceed())
	require.True(t, plan.RequiresConfirmation())
	assertPreserved(t, plan, service, history)
	require.Len(t, plan.Changes(), 1)
	require.Equal(t, key, plan.Changes()[0].Resource)
	requireCode(t, plan.Check("", false), DeletionConfirmationRequired)
	require.NoError(t, plan.Check(plan.ImpactVersion(), true))
	data, err := json.Marshal(manifest(plan, PolicyVersion))
	require.NoError(t, err)
	require.False(t, strings.Contains(string(data), credential), "credential in canonical manifest")
	require.Contains(t, string(data), key.ID)
	require.Equal(t, "deletion-safety-spec1-v2", PolicyVersion)
}
