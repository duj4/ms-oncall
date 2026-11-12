package deleteaudit

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func testEvent() Event {
	root := uuid.New()
	ordinal := 0
	return Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "success_witness", Operation: "user.delete", RootType: "user", RootID: &root, RootOrdinal: &ordinal, ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", TargetOrgResolution: "unknown", BeforeContext: &Before{Version: 1, UserID: root, UserRole: "user", RowVersion: math.MaxUint32, TargetOrgResolution: "unknown", OrganizationRole: "unknown"}, Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target", Outcome: "committed", Reason: "deleted", OccurredAt: time.Now()}
}

func TestUserDeleteAuditRootAndReceipt(t *testing.T) {
	e := testEvent()
	require.NoError(t, e.Validate())
	r := Receipt{Event: e, DeletedUserID: *e.RootID, DeletedRole: e.BeforeContext.UserRole, DeletedRowVersion: e.BeforeContext.RowVersion}
	require.NoError(t, r.Validate())
	for name, change := range map[string]func(*Event){
		"root": func(e *Event) { e.RootID = ID(uuid.New()) }, "actor": func(e *Event) { e.ActorID = ID(uuid.New()) }, "missing actor": func(e *Event) { e.ActorKind = "human" }, "unknown success": func(e *Event) { e.ActorKind = "unknown" }, "home target": func(e *Event) { e.TargetOrganizationID = ID(uuid.New()) }, "version": func(e *Event) { e.SchemaVersion = 2 }, "ordinal": func(e *Event) { i := 100; e.RootOrdinal = &i }, "count": func(e *Event) { e.EffectCount = 1 }, "bytes": func(e *Event) { e.EffectJSONBytes = 1 }, "failure before": func(e *Event) { e.RecordKind = "attempt_observation" },
	} {
		t.Run(name, func(t *testing.T) { copy := e; change(&copy); require.Error(t, copy.Validate()) })
	}
	r.DeletedRowVersion--
	require.Error(t, r.Validate())
	e = testEvent()
	e.ActorKind = "human"
	e.ActorID = ID(uuid.New())
	e.HomeOrganizationID = ID(uuid.New())
	e.AuthoritySource = "current_local_user_organization_at_admission"
	e.AuthorityRole = "platform_admin"
	e.OrganizationRole = "ORG_MEMBER"
	require.NoError(t, e.Validate(), "Normal PA unknown Target is existing behavior")
	for _, resolution := range []string{"known_normal", "known_default"} {
		org := uuid.New()
		if resolution == "known_default" {
			org = uuid.MustParse("296e2656-7221-53fe-bd0a-832d24ccfd03")
		}
		e.TargetOrganizationID, e.TargetOrgResolution = &org, resolution
		b := *e.BeforeContext
		b.AssignmentPresent = true
		n := uint32(1)
		b.AssignmentRowVersion = &n
		b.OrganizationRole = "NONE"
		b.TargetOrganizationID, b.TargetOrgResolution = &org, resolution
		e.BeforeContext = &b
		require.NoError(t, e.Validate())
		require.NotEqual(t, e.HomeOrganizationID, e.TargetOrganizationID)
	}
}

func TestUserDeleteAuditResidentBudget(t *testing.T) {
	var b Budget
	require.NoError(t, b.Reserve(MaxCaptureUnits, MaxActiveJSONBytes))
	require.ErrorIs(t, b.Reserve(1, 0), ErrCapacity)
	require.ErrorIs(t, b.Reserve(0, 1), ErrCapacity)
	require.NoError(t, b.Release(MaxCaptureUnits, MaxActiveJSONBytes))
	for range 5000 {
		require.NoError(t, b.Reserve(1, MaxLeafBytes))
		require.NoError(t, b.Release(1, MaxLeafBytes))
	}
	require.Equal(t, MaxCaptureUnits, b.HighUnits)
	require.Equal(t, MaxActiveJSONBytes, b.HighBytes)
	require.Zero(t, b.Units)
	require.Zero(t, b.Bytes)
	require.Error(t, b.Release(1, 0))
	require.Error(t, b.Reserve(-1, 0))
}

func TestUserDeleteAuditClosedEffectsAndPrecision(t *testing.T) {
	root := uuid.New()
	for typ, p := range projections {
		t.Run(typ, func(t *testing.T) {
			before := map[string]any{}
			for k, kind := range p.Fields {
				switch kind {
				case "u":
					before[k] = root
				case "U", "I", "T":
					before[k] = nil
				case "i", "o":
					before[k] = int64(math.MaxInt64)
				case "j":
					before[k] = int64(math.MaxInt32)
				case "w":
					before[k] = int64(127)
				case "c":
					before[k] = "23:59:59.999999"
				case "x":
					before[k] = int64(math.MaxUint32)
				case "b":
					before[k] = true
				case "t":
					before[k] = "infinity"
				default:
					before[k] = strings.Split(kind, "|")[0]
				}
			}
			if typ == "user_override" {
				before["add_user_id"] = root
			}
			if typ == "user_status_contact_setting" {
				before["user_id"] = uuid.New()
			}
			raw, err := json.Marshal(before)
			require.NoError(t, err)
			key := fmt.Sprint(before[p.Key])
			f := Effect{EffectID: uuid.New(), ResourceType: typ, ResourceKey: key, TransitionSlot: "row", TriggerUserID: root, OrgResolution: "unknown", Before: raw, After: json.RawMessage("null"), Change: "deleted", Provenance: "IMPLICIT_FK_CASCADE", DeletionMechanism: "fk_cascade"}
			switch typ {
			case "user_favorite", "user_organization_assignment":
				f.Change = "relationship_removed"
			case "rotation_participant":
				f.Change, f.Provenance, f.DeletionMechanism = "relationship_removed", "IMPLICIT_APPLICATION_DELETE", "explicit_sql"
			case "rotation_state":
				f.Provenance, f.DeletionMechanism = "IMPLICIT_TRIGGER_DELETE", "trigger_delete"
			case "rotation_participant_count":
				before["participant_count"] = int64(1)
				f.Before, _ = json.Marshal(before)
				before["participant_count"] = int64(0)
				f.After, _ = json.Marshal(before)
				f.Change, f.Provenance, f.DeletionMechanism = "state_updated", "IMPLICIT_TRIGGER_UPDATE", "trigger_update"
			case "user_status_contact_setting":
				before["contact_method_id"] = uuid.New()
				f.Before, _ = json.Marshal(before)
				before["contact_method_id"] = nil
				f.After, _ = json.Marshal(before)
				f.Change, f.Provenance, f.DeletionMechanism = "relationship_cleared", "IMPLICIT_FK_SET_NULL", "fk_set_null"
			}
			require.NoError(t, f.Validate(root))
			encoded, err := json.Marshal(f)
			require.NoError(t, err)
			decoded, err := DecodeEffect(encoded)
			require.NoError(t, err)
			require.NoError(t, decoded.Validate(root))
			if p.Fields[p.Key] == "i" {
				require.Contains(t, string(encoded), "9223372036854775807")
			}
			before["password_hash"] = "SYNTHETIC_PRIVATE"
			bad, _ := json.Marshal(before)
			f.Before = bad
			require.Error(t, f.Validate(root))
			f = decoded
			f.TriggerUserID = uuid.New()
			require.Error(t, f.Validate(root))
			padded := append(append([]byte{}, encoded...), []byte(strings.Repeat(" ", MaxLeafBytes-len(encoded)))...)
			_, err = DecodeEffect(padded)
			require.NoError(t, err)
			_, err = DecodeEffect(append(padded, ' '))
			require.ErrorIs(t, err, ErrCapacity)
		})
	}
	for _, stamp := range []string{"infinity", "-infinity", "10000-01-01T00:00:00Z", "294276-01-01T00:00:00+00:00", "0001-01-01T00:00:00Z BC"} {
		raw, _ := json.Marshal(stamp)
		require.True(t, scalar(raw, "t"), stamp)
	}
	require.False(t, scalar(json.RawMessage(`"SYNTHETIC_PRIVATE"`), "t"))
}

func TestUserDeleteAuditWitnessTampering(t *testing.T) {
	e := testEvent()
	w := ExplicitWitness{EventID: uuid.New(), ResourceType: "contact_method", ResourceID: uuid.New(), OwnerID: *e.RootID, TargetOrgResolution: "unknown", RowVersion: 1, CauseUserID: *e.RootID, CauseEventID: e.EventID, RequestID: e.RequestID, ExecutionID: e.ExecutionID, AttemptID: e.AttemptID, OwnerFK: true, Verified: true}
	e.RelatedExplicitEvents = []RelatedExplicitEvent{{EventID: w.EventID, ResourceType: w.ResourceType, ResourceID: w.ResourceID}}
	r := Receipt{Event: e, DeletedUserID: *e.RootID, DeletedRole: e.BeforeContext.UserRole, DeletedRowVersion: e.BeforeContext.RowVersion, Witnesses: []ExplicitWitness{w}}
	require.NoError(t, r.Validate())
	for name, change := range map[string]func(*ExplicitWitness){"attempt": func(w *ExplicitWitness) { w.AttemptID = uuid.New() }, "cause": func(w *ExplicitWitness) { w.CauseEventID = uuid.New() }, "owner": func(w *ExplicitWitness) { w.OwnerID = uuid.New() }, "pending": func(w *ExplicitWitness) { w.Verified = false }, "intent": func(w *ExplicitWitness) { w.IntentOrdinal = 50 }, "parent": func(w *ExplicitWitness) { w.ParentCMID = ID(uuid.New()) }, "xmin": func(w *ExplicitWitness) { w.RowVersion = 0 }} {
		t.Run(name, func(t *testing.T) {
			copy := r
			changed := w
			change(&changed)
			copy.Witnesses = []ExplicitWitness{changed}
			require.Error(t, copy.Validate())
		})
	}
}

func TestUserDeleteAuditEncodedByteBoundaries(t *testing.T) {
	// Exercise the exact encoder-size guard independently of the closed field
	// validator: a valid fixed-field header cannot be inflated arbitrarily.
	for _, limit := range []int{MaxLeafBytes, MaxHeaderBytes} {
		value := struct {
			Text    string `json:"text"`
			Null    *bool  `json:"null"`
			Integer int64  `json:"integer"`
		}{Text: "汉<&", Integer: math.MaxInt64}
		base, err := json.Marshal(value)
		require.NoError(t, err)
		for _, delta := range []int{-1, 0, 1} {
			copy := value
			copy.Text += strings.Repeat("x", limit+delta-len(base))
			raw, err := json.Marshal(copy)
			require.NoError(t, err)
			require.Len(t, raw, limit+delta)
			require.Contains(t, string(raw), `\u003c\u0026`)
			require.Contains(t, string(raw), `9223372036854775807`)
			if delta > 0 {
				require.ErrorIs(t, checkJSONBytes(raw, limit), ErrCapacity)
			} else {
				require.NoError(t, checkJSONBytes(raw, limit))
			}
		}
	}
	e := testEvent()
	for range 100 {
		e.RelatedExplicitEvents = append(e.RelatedExplicitEvents, RelatedExplicitEvent{EventID: uuid.New(), ResourceType: "notification_rule", ResourceID: uuid.New()})
	}
	require.NoError(t, e.Validate())
	raw, err := json.Marshal(e.Canonical())
	require.NoError(t, err)
	t.Logf("100-reference closed header Go JSON bytes=%d (limit=%d)", len(raw), MaxHeaderBytes)
}
