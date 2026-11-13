package authsubjectdeleteaudit

import (
	"database/sql"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func systemEvent() Event {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), Operation: "auth_subject.delete", RootType: "auth_subject", ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", TargetOrgResolution: "unknown", OccurredAt: now, RecordedAt: now}
}

func successEvent(id int64) Event {
	e := systemEvent()
	owner := uuid.New()
	identity := Identity(id)
	e.RootID = &identity
	e.RootOwnerUserID = &owner
	e.RecordKind = "success_witness"
	e.Outcome = "committed"
	e.Reason = "deleted"
	e.Provenance = "EXPLICIT"
	e.Cause = "explicit_target"
	e.DeletionMechanism = "explicit_sql"
	e.BeforeContext = &Before{Version: 1, ID: identity, UserID: owner, RowVersion: 42}
	return e
}

func TestIdentityFullSignedDomainAndClosedDecode(t *testing.T) {
	for _, id := range []int64{math.MinInt64, -1, 0, 1, 1<<53 - 1, 1 << 53, 1<<53 + 1, math.MaxInt64} {
		e := successEvent(id)
		require.NoError(t, e.Validate())
		raw, err := json.Marshal(e)
		require.NoError(t, err)
		decoded, err := Decode(raw)
		require.NoError(t, err)
		require.Equal(t, id, int64(*decoded.RootID))
		require.Contains(t, string(raw), `"root_id":"`)
	}
	for _, raw := range []string{`1`, `null`, `"01"`, `"-0"`, `"+1"`, `"1.0"`, `"1e1"`, `"9223372036854775808"`, `"-9223372036854775809"`} {
		var id Identity
		require.Error(t, json.Unmarshal([]byte(raw), &id))
	}
	raw, _ := json.Marshal(successEvent(9))
	for _, bad := range []string{
		strings.Replace(string(raw), `"root_id":"9"`, `"root_id":9`, 1),
		strings.Replace(string(raw), `"version":1,`, "", 1),
		strings.Replace(string(raw), `"cm_id":null,`, "", 1),
		strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(string(raw), `"version":1`, `"version":1,"ProviderID":"SYNTHETIC_PRIVATE"`, 1),
		strings.Replace(string(raw), `"schema_version":1,`, "", 1),
		strings.TrimSuffix(string(raw), "}") + `,"metadata":"SYNTHETIC_PRIVATE"}`,
		string(raw) + ` {}`,
	} {
		_, err := Decode([]byte(bad))
		require.ErrorIs(t, err, ErrInvalid)
	}
}

func TestReceiptBindsAllEvidenceAndConsumesOnce(t *testing.T) {
	tx, other := new(sql.Tx), new(sql.Tx)
	e := systemEvent()
	owner := uuid.New()
	cm := uuid.New()
	b := Before{Version: 1, ID: Identity(math.MinInt64), UserID: owner, CMID: &cm, RowVersion: 42}
	r, err := NewReceipt(tx, e, b, b, owner, true)
	require.NoError(t, err)
	for _, change := range []func(*Before){func(v *Before) { v.ID++ }, func(v *Before) { v.UserID = uuid.New() }, func(v *Before) { v.CMID = nil }, func(v *Before) { v.RowVersion++ }} {
		returned := b
		change(&returned)
		_, err = NewReceipt(tx, e, b, returned, owner, true)
		require.ErrorIs(t, err, ErrInvalid)
	}
	_, err = NewReceipt(tx, e, b, b, owner, false)
	require.ErrorIs(t, err, ErrInvalid)
	_, err = NewReceipt(tx, e, b, b, uuid.New(), true)
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorIs(t, AppendReceipt(t.Context(), other, r, e), ErrInvalid)
	changed := e
	changed.AttemptID = uuid.New()
	require.ErrorIs(t, AppendReceipt(t.Context(), tx, r, changed), ErrInvalid)
	changed = e
	changed.ActorKind = "unknown"
	require.ErrorIs(t, AppendReceipt(t.Context(), tx, r, changed), ErrInvalid)
	r.used = true
	require.ErrorIs(t, AppendReceipt(t.Context(), tx, r, e), ErrInvalid)
	cm = uuid.New()
	require.NotEqual(t, cm, *r.event.BeforeContext.CMID, "receipt owns its projection")
}

func TestSuccessAndObservationCannotBeConfused(t *testing.T) {
	// Nullable is not the same as the actual all-zero business UUID value.
	zero := uuid.Nil
	fullDomain := successEvent(0)
	fullDomain.RootOwnerUserID = &zero
	fullDomain.ParentCMID = &zero
	fullDomain.BeforeContext.UserID = zero
	fullDomain.BeforeContext.CMID = &zero
	require.NoError(t, fullDomain.Validate())
	zeroRaw, _ := json.Marshal(fullDomain)
	_, zeroErr := Decode([]byte(strings.Replace(string(zeroRaw), `"user_id":"00000000-0000-0000-0000-000000000000"`, `"user_id":null`, 1)))
	require.ErrorIs(t, zeroErr, ErrInvalid)
	for _, change := range []func(*Event){func(e *Event) { e.RootID = nil }, func(e *Event) { e.ActorKind = "unknown" }, func(e *Event) { e.BeforeContext.RowVersion = 0 }, func(e *Event) { e.BeforeContext.ID++ }, func(e *Event) { e.Outcome = "commit_unknown" }, func(e *Event) { e.Cause = "fk_cascade" }} {
		e := successEvent(0)
		change(&e)
		require.ErrorIs(t, e.Validate(), ErrInvalid)
	}
	e := systemEvent()
	e.RecordKind = "attempt_observation"
	e.Outcome = "commit_unknown"
	e.Reason = "commit_unconfirmed"
	require.NoError(t, e.Validate())
	e.BeforeContext = &Before{}
	require.ErrorIs(t, e.Validate(), ErrInvalid)
}
