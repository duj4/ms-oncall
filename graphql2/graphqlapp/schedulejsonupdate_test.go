package graphqlapp

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	audit "github.com/target/goalert/schedule/jsonupdateaudit"
)

type scheduleJSONFailSigner struct{}

func (scheduleJSONFailSigner) Sign([]byte) ([]byte, error) {
	return nil, errors.New("synthetic signer fault")
}
func (scheduleJSONFailSigner) Verify([]byte, []byte) (bool, bool) { return false, false }
func TestScheduleJSONVersionAndTimeAttenuation(t *testing.T) {
	at := time.Now()
	signer := previewTestSigner{}
	version, err := encodeScheduleJSONVersion(signer, hexDigest([]byte("intent")), at)
	require.NoError(t, err)
	_, err = decodeScheduleJSONVersion(signer, version, at.Add(time.Minute))
	require.NoError(t, err)
	for _, now := range []time.Time{at.Add(-time.Nanosecond), at.Add(scheduleJSONConsentTTL + time.Nanosecond)} {
		_, err := decodeScheduleJSONVersion(signer, version, now)
		require.Error(t, err)
	}
	_, err = decodeScheduleJSONVersion(signer, version+"forged", at)
	require.Error(t, err)
	_, err = encodeScheduleJSONVersion(scheduleJSONFailSigner{}, "digest", at)
	require.Error(t, err)
	approved := []audit.Effect{{Coverage: audit.Coverage{Kind: "temporary", Start: "1", End: "100"}, Change: "coverage_removed", Source: "EXPLICIT"}}
	smaller := []audit.Effect{{Coverage: audit.Coverage{Kind: "temporary", Start: "5", End: "100"}, Change: "coverage_removed", Source: "EXPLICIT"}}
	require.True(t, scheduleJSONAttenuates(approved, smaller))
	require.False(t, scheduleJSONAttenuates(smaller, approved))
	for _, field := range []string{"setTemporarySchedule", "clearTemporarySchedules", "previewSetTemporarySchedule", "previewClearTemporarySchedules"} {
		op := "mutation"
		if field[:3] == "pre" {
			op = "query"
		}
		ctx := asOperationContext(t, op+`{ privateAlias:`+field+`(input:{scheduleID:"synthetic"}) }`, "", field)
		require.True(t, scheduleTargetUpdateDiagnosticsSelected(ctx))
	}
}

func TestScheduleJSONPlanSupportsFullShiftLimit(t *testing.T) {
	before := []audit.Coverage{{Kind: "temporary", Start: "0", End: "100"}}
	for n := 0; n < 150; n++ {
		before = append(before, audit.Coverage{Kind: "fixed_shift", UserID: uuid.NewString(), Start: "0", End: "100"})
	}
	before, err := audit.Canonical(before)
	require.NoError(t, err)
	effects, err := audit.Diff(before, []audit.Coverage{})
	require.NoError(t, err)
	plan, err := scheduleJSONPlan(audit.Event{ScheduleID: uuid.New(), EnvelopeID: 1, Operation: audit.Clear, Effects: effects}, hexDigest([]byte("synthetic-scope")))
	require.NoError(t, err)
	require.True(t, plan.CanProceed())
	require.True(t, plan.RequiresConfirmation())
	require.Len(t, plan.Impacts(), 151)
}
