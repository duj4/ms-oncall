package usersessioncompat

import (
	"bytes"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth/authtoken"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/util/log"
)

func TestUserSessionCompatSignedAuthorityMatrix(t *testing.T) {
	f := newFixture(t)
	h := f.h
	for _, tc := range []struct {
		actor, owner    string
		denied, revoked bool
	}{
		{"om", "om", false, true}, {"oa", "oa", false, true},
		{"pam", "b", false, true}, {"paa", "om", false, true},
		{"pd0", "b", false, true}, {"pd0", "pd0", true, false},
		{"om", "b", false, false}, {"oa", "b", false, false},
		{"ba", "om", false, false}, {"od", "b", true, false},
	} {
		t.Run(tc.actor+"_"+tc.owner, func(t *testing.T) {
			id, safe := createSession(t, h, h.UUID(tc.owner))
			before := successCount(t, h)
			r := request(t, h, f.tokens[tc.actor], sessionCompatUIMutation, map[string]any{"id": id})
			require.Equal(t, tc.denied, len(r["errors"]) > 0)
			sessionIdentityAbsent(t, r["errors"], id, f.tokens[tc.actor])
			remaining := countSQL(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1`, id)
			if !tc.revoked {
				require.EqualValues(t, 1, remaining)
				require.Equal(t, before, successCount(t, h))
				require.Zero(t, countSQL(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=$1`, safe))
				return
			}
			sessionCompatSucceeded(t, r)
			require.Zero(t, remaining)
			require.Equal(t, before+1, successCount(t, h))
			home, target := h.UUID("s2-org-a"), h.UUID("s2-org-a")
			if tc.actor == "pd0" {
				home = organization.DefaultOrganizationID
			}
			if tc.owner == "b" {
				target = h.UUID("s2-org-b")
			}
			var bound bool
			err := h.App().DB().QueryRowContext(t.Context(), `SELECT e.actor_id=$2 AND e.home_organization_id=$3 AND d.target_user_id=$4 AND d.target_organization_id=$5 FROM user_session_revoke_audit_events e JOIN user_session_revoke_audit_details d USING(event_id) WHERE d.session_audit_id=$1`, safe, h.UUID(tc.actor), home, h.UUID(tc.owner), target).Scan(&bound)
			require.NoError(t, err)
			require.True(t, bound, "authority and target Organization are server-resolved independently")
		})
	}
	for _, actor := range []string{"om", "pam"} {
		t.Run(actor+"_batch_duplicates_missing", func(t *testing.T) {
			one, safe1 := createSession(t, h, h.UUID("om"))
			two, safe2 := createSession(t, h, h.UUID("om"))
			foreign, foreignSafe := createSession(t, h, h.UUID("b"))
			before := successCount(t, h)
			r := request(t, h, f.tokens[actor], selectedQuery(one, two, one, foreign, uuid.NewString()), nil)
			sessionCompatSucceeded(t, r)
			require.Zero(t, countSQL(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=ANY($1)`, []string{one, two}))
			require.EqualValues(t, 2, countSQL(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=ANY($1)`, []uuid.UUID{safe1, safe2}))
			want := int64(1)
			if actor == "pam" {
				want = 0
			}
			require.Equal(t, want, countSQL(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1`, foreign))
			require.Equal(t, 1-want, countSQL(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=$1`, foreignSafe))
			require.Equal(t, before+1, successCount(t, h))
		})
	}
}

type logCanary struct {
	next      io.Writer
	private   []string
	leaked    atomic.Bool
	completed atomic.Int64
}

func (w *logCanary) Write(p []byte) (int, error) {
	for _, value := range w.private {
		if bytes.Contains(p, []byte(value)) {
			w.leaked.Store(true)
		}
	}
	if bytes.Contains(p, []byte("request complete")) {
		w.completed.Add(1)
	}
	return w.next.Write(p)
}

func TestUserSessionCompatNonCredentialIdentityAndDiagnostics(t *testing.T) {
	f := newFixture(t)
	h := f.h
	id, safe := createSession(t, h, h.UUID("om"))
	token, err := (authtoken.Token{Version: 1, ID: safe, Type: authtoken.TypeSession}).Encode(h.App().SessionKeyring.Sign)
	require.NoError(t, err)
	logger := log.FromContext(h.App().Context(t.Context()))
	logger.EnableDebug()
	previous := logger.Logrus().Out
	canary := &logCanary{next: previous, private: []string{id, f.sessions["pam"], f.tokens["pam"], token}}
	logger.SetOutput(canary)
	defer logger.SetOutput(previous)
	// Neither the real locator nor its audit identity is a credential. Even a
	// genuinely signed credential carrying the safe audit identity cannot log in.
	for _, credential := range []string{id, safe.String(), token} {
		status, _ := requestRaw(t, h, credential, selectedQuery(id), nil)
		require.Equal(t, 401, status)
	}
	before := successCount(t, h)
	sessionCompatSucceeded(t, request(t, h, f.tokens["pam"], sessionCompatUIMutation, map[string]any{"id": safe.String()}))
	require.Equal(t, before, successCount(t, h), "safe audit identity cannot locate a live Session")
	sessionCompatSucceeded(t, request(t, h, f.tokens["pam"], sessionCompatUIMutation, map[string]any{"id": id}))
	var next uuid.UUID
	err = h.App().DB().QueryRowContext(t.Context(), `INSERT INTO auth_user_sessions(id,user_id) VALUES($1,$2) RETURNING audit_resource_id`, id, h.UUID("om")).Scan(&next)
	require.True(t, err == nil, "recreate synthetic Session (details withheld)")
	require.True(t, next != safe && next.String() != id, "new lifecycle must have a fresh persistent safe identity")
	sessionCompatSucceeded(t, request(t, h, f.tokens["pam"], sessionCompatUIMutation, map[string]any{"id": id}))
	require.Equal(t, before+2, successCount(t, h))
	require.EqualValues(t, 2, countSQL(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=ANY($1)`, []uuid.UUID{safe, next}))
	var stored []byte
	require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT jsonb_agg(to_jsonb(e)||jsonb_build_object('detail',to_jsonb(d)))::text FROM user_session_revoke_audit_events e JOIN user_session_revoke_audit_details d USING(event_id) WHERE d.session_audit_id=ANY($1)`, []uuid.UUID{safe, next}).Scan(&stored))
	sessionIdentityAbsent(t, stored, id, f.sessions["pam"], f.tokens["pam"])
	require.Eventually(t, func() bool { return canary.completed.Load() >= 6 }, time.Second, 10*time.Millisecond)
	require.False(t, canary.leaked.Load(), "debug/application/access logs must omit Session material")
}
