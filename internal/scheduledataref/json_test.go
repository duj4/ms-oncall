package scheduledataref

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestUsersCompleteStrictAndStable(t *testing.T) {
	sched := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	a, b := uuid.MustParse("22222222-2222-4222-8222-222222222222"), uuid.MustParse("33333333-3333-4333-8333-333333333333")
	shift := func(id uuid.UUID) string {
		return `{"Start":"2026-01-01T00:00:00Z","End":"2026-01-02T00:00:00Z","UserID":"` + id.String() + `"}`
	}
	raw := `{"V1":{"TemporarySchedules":[{"Start":"2026-01-01T00:00:00Z","End":"2026-01-02T00:00:00Z","Shifts":[` + shift(b) + `,` + shift(a) + `,` + shift(b) + `]}],"OnCallNotificationRules":null}}`
	users, err := Users([]byte(raw), sched)
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{a, b}, users, "ended references must also be locked, in sorted order")
	for name, bad := range map[string]string{
		"envelope-null": "null", "envelope-array": "[]", "envelope-empty": "{}", "version-null": `{"V1":null}`,
		"missing-temporary": `{"V1":{"OnCallNotificationRules":[]}}`,
		"unknown-envelope":  strings.Replace(raw, `"V1":`, `"V2":{},"V1":`, 1),
		"unknown-temporary": strings.Replace(raw, `"Shifts":`, `"Unknown":true,"Shifts":`, 1),
		"unknown-shift":     strings.Replace(raw, `"UserID":`, `"Unknown":true,"UserID":`, 1),
		"bad-user":          strings.ReplaceAll(raw, b.String(), "unknown-user"),
		"zero-user":         strings.ReplaceAll(raw, b.String(), uuid.Nil.String()),
		"bad-time":          strings.Replace(raw, "2026-01-01T00:00:00Z", "bad-time", 1),
		"empty-window":      strings.ReplaceAll(raw, "2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z"),
		"missing-shifts":    `{"V1":{"TemporarySchedules":[{"Start":"2026-01-01T00:00:00Z","End":"2026-01-02T00:00:00Z"}]}}`,
		"null-shift":        `{"V1":{"TemporarySchedules":[{"Start":"2026-01-01T00:00:00Z","End":"2026-01-02T00:00:00Z","Shifts":[null]}]}}`,
		"unknown-rule":      `{"V1":{"TemporarySchedules":[],"OnCallNotificationRules":[{"ID":"` + sched.String() + `:0","ChannelID":"` + a.String() + `","Unknown":true}]}}`,
		"byte-budget":       strings.Repeat(" ", MaxBytes) + raw,
	} {
		t.Run(name, func(t *testing.T) { got, err := Users([]byte(bad), sched); require.Error(t, err); require.Nil(t, got) })
	}
}

func TestKnownSliceShapes(t *testing.T) {
	sched := uuid.New()
	for _, field := range []string{"TemporarySchedules", "OnCallNotificationRules"} {
		for _, value := range []string{"null", "[]", "{}", `"string"`, "0", "false", "[null]"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				v1 := map[string]json.RawMessage{"TemporarySchedules": []byte("[]"), "OnCallNotificationRules": []byte("[]")}
				v1[field] = []byte(value)
				raw, err := json.Marshal(map[string]any{"V1": v1})
				require.NoError(t, err)
				got, err := Users(raw, sched)
				if value == "null" || value == "[]" {
					require.NoError(t, err)
					require.Empty(t, got)
				} else {
					require.Error(t, err)
					require.Nil(t, got)
				}
			})
		}
	}
	_, err := Slice([]byte(`[{},{}]`), 1)
	require.Error(t, err)
	_, err = Slice([]byte(`null`), -1)
	require.Error(t, err)
	_, err = Slice([]byte(`[] true`), 1)
	require.Error(t, err)
}
