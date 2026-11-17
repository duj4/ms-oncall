package deleteaudit

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/util/sqlutil"
)

func TestSessionSnapshotContracts(t *testing.T) {
	root, locator, safe := uuid.New(), uuid.New(), uuid.New()
	for _, tc := range []struct {
		name        string
		fields      map[string]any
		read, write bool
	}{
		{"historical", map[string]any{"id": locator, "user_id": root, "row_version": 1}, true, false},
		{"safe", map[string]any{"version": 2, "audit_resource_id": safe, "user_id": root, "row_version": 1}, true, true},
		{"unversioned_safe", map[string]any{"audit_resource_id": safe, "user_id": root, "row_version": 1}, false, false},
		{"missing_safe", map[string]any{"version": 2, "user_id": root, "row_version": 1}, false, false},
		{"zero_safe", map[string]any{"version": 2, "audit_resource_id": uuid.Nil, "user_id": root, "row_version": 1}, false, false},
		{"raw_field", map[string]any{"version": 2, "id": locator, "user_id": root, "row_version": 1}, false, false},
		{"extra_raw", map[string]any{"version": 2, "audit_resource_id": safe, "id": locator, "user_id": root, "row_version": 1}, false, false},
		{"unknown", map[string]any{"version": 3, "audit_resource_id": safe, "user_id": root, "row_version": 1}, false, false},
		{"string_version", map[string]any{"version": "2", "audit_resource_id": safe, "user_id": root, "row_version": 1}, false, false},
		{"wrong_type", map[string]any{"version": 2, "audit_resource_id": 1, "user_id": root, "row_version": 1}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.fields)
			require.NoError(t, err)
			key := safe.String()
			if tc.name == "historical" {
				key = locator.String()
			}
			f := Effect{EffectID: uuid.New(), ResourceType: "user_session", ResourceKey: key, TransitionSlot: "row", TriggerUserID: root, OrgResolution: "unknown", Change: "deleted", Provenance: "IMPLICIT_FK_CASCADE", DeletionMechanism: "fk_cascade", Before: raw, After: json.RawMessage("null")}
			require.True(t, (ValidateSnapshot("user_session", key, raw) == nil) == tc.read)
			require.True(t, (f.Validate(root) == nil) == tc.read)
			require.True(t, (f.ValidateForWrite(root) == nil) == tc.write)
			encoded, err := json.Marshal(f)
			require.NoError(t, err)
			decoded, err := DecodeEffect(encoded)
			require.NoError(t, err)
			require.True(t, (decoded.Validate(root) == nil) == tc.read)
		})
	}
}

func TestSessionCaptureErrorsAreSafeAndRetryable(t *testing.T) {
	locator := uuid.NewString()
	err := sessionError(&pgconn.PgError{Code: "23505", Message: locator, Detail: locator})
	require.ErrorIs(t, err, ErrInvalid)
	require.True(t, err.Error() != locator)
	for _, code := range []string{"40001", "40P01"} {
		err = sessionError(&pgconn.PgError{Code: code, Message: locator, Detail: locator})
		mapped := sqlutil.MapError(err)
		require.NotNil(t, mapped)
		require.Equal(t, code, mapped.Code)
		require.True(t, mapped.Message != locator && mapped.Detail == "")
	}
}
