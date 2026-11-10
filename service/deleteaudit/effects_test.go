package deleteaudit

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func testEffect(e Event, typ string, id int64) Effect {
	f := Effect{EffectID: uuid.New(), ResourceType: typ, ResourceNumericID: &id, OwnerOrgResolution: "not_applicable", TargetOrganizationID: e.TargetOrganizationID, Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: "service_delete", Relation: "service.alert", Change: "deleted"}
	if typ == IntegrationKey {
		safe := uuid.New()
		f.ResourceUUID = &safe
		f.ResourceNumericID = nil
		f.Relation = "service.integration_key"
	}
	if typ == ServiceFavorite {
		owner := uuid.New()
		f.OwnerUserID = &owner
		f.OwnerOrgResolution = "unknown"
		f.Relation = "service.favorite"
		f.Change = "relationship_removed"
	}
	return f
}

func TestServiceEffectsU01TypedSchemaAndU04Privacy(t *testing.T) {
	e := validEvent()
	for _, typ := range []string{IntegrationKey, Alert, ServiceFavorite} {
		e.Effects = append(e.Effects, testEffect(e, typ, math.MaxInt64))
	}
	require.NoError(t, e.Validate())
	raw, err := json.Marshal(e.Canonical().Effects)
	require.NoError(t, err)
	var fields []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &fields))
	for _, f := range fields {
		require.Len(t, f, 13)
	}
	require.Contains(t, string(raw), "9223372036854775807")
	for _, bad := range []string{"credential", "token", "config", "name", "summary", "email", "phone", "metadata"} {
		require.NotContains(t, string(raw), `"`+bad+`"`)
	}
	for name, mutate := range map[string]func(*Event){
		"version": func(e *Event) { e.EffectsVersion = 0 }, "execution": func(e *Event) { e.ExecutionID = uuid.Nil },
		"type": func(e *Event) { e.Effects[0].ResourceType = "heartbeat_monitor" }, "id": func(e *Event) { e.Effects[0].EffectID = uuid.Nil },
		"target": func(e *Event) { e.Effects[0].TargetOrganizationID = uuid.New() }, "owner": func(e *Event) { v := uuid.New(); e.Effects[0].OwnerUserID = &v },
		"numeric": func(e *Event) { v := int64(0); e.Effects[1].ResourceNumericID = &v }, "provenance": func(e *Event) { e.Effects[0].Provenance = "IMPLICIT" },
		"cause": func(e *Event) { e.Effects[0].Cause = "explicit_target" }, "owner org": func(e *Event) { e.Effects[2].OwnerOrgResolution = "known_default" },
	} {
		t.Run(name, func(t *testing.T) {
			c := e.Canonical() // canonical order is alert,key,favorite
			// Mutations are expressed on the original typed order.
			c.Effects = append([]Effect{}, e.Effects...)
			mutate(&c)
			require.Error(t, c.Validate())
		})
	}
}

func TestServiceEffectsU02SortingDuplicatesAndCapacity(t *testing.T) {
	e := validEvent()
	for _, n := range []int64{math.MaxInt64, 10, 2} {
		e.Effects = append(e.Effects, testEffect(e, Alert, n))
	}
	c := e.Canonical()
	require.EqualValues(t, 2, *c.Effects[0].ResourceNumericID)
	require.Equal(t, c, c.Canonical())
	require.NoError(t, c.Validate())
	c.Effects = append(c.Effects, c.Effects[0])
	require.ErrorIs(t, c.Validate(), ErrInvalid)
	e.Effects = nil
	for i := 1; i <= MaxEffects; i++ {
		e.Effects = append(e.Effects, testEffect(e, Alert, int64(i)))
	}
	require.NoError(t, e.Validate())
	require.NoError(t, ValidateBatch([]Event{e}))
	other := validEvent()
	other.Effects = []Effect{testEffect(other, Alert, MaxEffects+1)}
	require.ErrorIs(t, ValidateBatch([]Event{e, other}), ErrCapacity)
	e.Effects = append(e.Effects, testEffect(e, Alert, MaxEffects+1))
	require.ErrorIs(t, e.Validate(), ErrCapacity)
	e = validEvent()
	e.Effects = []Effect{testEffect(e, Alert, 1)}
	other = e
	other.ServiceID = uuid.New()
	require.ErrorIs(t, ValidateBatch([]Event{e, other}), ErrInvalid, "one actual child cannot attach to multiple roots")
}

func TestServiceEffectsU03ClassificationAndU06OutcomeSemantics(t *testing.T) {
	e := validEvent()
	f := testEffect(e, IntegrationKey, 0)
	for _, v := range [][3]string{{"EXPLICIT", "explicit_sql", "explicit_target"}, {"EXPLICIT", "fk_cascade", "service_delete"}, {"CASCADE", "fk_cascade", "service_delete"}} {
		f.Provenance, f.DeletionMechanism, f.Cause = v[0], v[1], v[2]
		e.Effects = []Effect{f}
		require.NoError(t, e.Validate())
	}
	// Future pure receipt modeling adds no production Alert DELETE route.
	f = testEffect(e, Alert, 1)
	f.Provenance, f.DeletionMechanism, f.Cause = "EXPLICIT", "explicit_sql", "explicit_target"
	e.Effects = []Effect{f}
	require.NoError(t, e.Validate())
	for _, outcome := range []string{"tx_failed", "commit_unknown"} {
		observation := e
		observation.Outcome = outcome
		observation.Reason = "write_failed"
		if outcome == "commit_unknown" {
			observation.Reason = "commit_unconfirmed"
		}
		require.ErrorIs(t, observation.Validate(), ErrInvalid)
		observation.Effects = nil
		require.NoError(t, observation.Validate())
		require.Len(t, e.Effects, 1, "unknown observation does not erase committed evidence")
	}
	e.Effects = nil
	require.NoError(t, e.Validate())
	raw, err := json.Marshal(e.Canonical().Effects)
	require.NoError(t, err)
	require.Equal(t, "[]", string(raw))
	e.ExecutionID = uuid.Nil
	e.EffectsVersion = 0
	require.ErrorIs(t, e.Validate(), ErrInvalid, "historical NULL is never a new complete-empty write")
}
