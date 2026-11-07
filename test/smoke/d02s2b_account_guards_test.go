package smoke

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth/authlink"
	"github.com/target/goalert/permission"
)

// Each independent Store guard is exercised by its actual signed HTTP entry.
func s2AccountGuards(t *testing.T, f *s2Fixture) {
	h := f.h
	for _, actor := range []string{"om", "oa", "pam", "paa"} {
		t.Run("account-guards/"+actor, func(t *testing.T) {
			pa := actor == "pam" || actor == "paa"
			t.Run("createUser", func(t *testing.T) {
				before := s2Snapshot(t, f)
				username := "s2-created-" + actor
				r := s2Call(t, f, "guard-createUser", actor, fmt.Sprintf(`mutation{createUser(input:{username:%q,password:"S2-Synthetic-Password-Only-814!",name:%q,role:user}){id name role}}`, username, "S2 Created "+actor), nil)
				if pa {
					s2Allow(t, r, "createUser")
					assert.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM users WHERE name=$1`, "S2 Created "+actor))
				} else {
					s2Deny(t, r)
					assert.Equal(t, before, s2Snapshot(t, f))
				}
			})
			t.Run("deleteUser", func(t *testing.T) {
				id := h.UUID("delete-target-" + actor)
				s2Exec(t, f, `INSERT INTO users(id,name,email,role) VALUES($1,'S2 disposable User','','user')`, id)
				before := s2Snapshot(t, f)
				r := s2Call(t, f, "guard-deleteAll-User", actor, fmt.Sprintf(`mutation{deleteAll(input:[{type:user,id:%q}])}`, id), nil)
				if pa {
					s2Allow(t, r, "deleteAll")
					assert.Equal(t, "0", s2Scalar(t, f, `SELECT count(*)::text FROM users WHERE id=$1`, id))
				} else {
					s2Deny(t, r)
					assert.Equal(t, before, s2Snapshot(t, f))
				}
			})
			for _, field := range []string{"sessions", "authSubjects"} {
				t.Run(field, func(t *testing.T) {
					fields := "id userAgent"
					if field == "authSubjects" {
						fields = "providerID subjectID userID"
					}
					before := s2Snapshot(t, f)
					r := s2Call(t, f, "guard-other-user-"+field, actor, fmt.Sprintf(`query{user(id:%q){id %s{%s}}}`, h.UUID("b"), field, fields), nil)
					if pa {
						s2Allow(t, r, "user")
						if field == "sessions" {
							assert.Contains(t, string(r.Raw), f.sessions["b"])
						}
					} else {
						// FIX1 hides the entire foreign Profile before nested
						// sensitive resolvers run. Assert the exact HTTP result.
						assert.Equal(t, 200, r.Status)
						assert.Empty(t, r.Errors)
						assert.Equal(t, "null", string(r.Data["user"]))
						assert.NotContains(t, string(r.Raw), f.sessions["b"])
						assert.NotContains(t, string(r.Raw), "s2-query-proof")
						// A visible same-Org non-owner must still reach and
						// fail the independent sensitive-field Store guard.
						r = s2Call(t, f, "guard-home-other-user-"+field, actor, fmt.Sprintf(`query{user(id:%q){id %s{%s}}}`, h.UUID("aowner"), field, fields), nil)
						s2Deny(t, r)
					}
					assert.Equal(t, before, s2Snapshot(t, f))
					r = s2Call(t, f, "guard-self-"+field, actor, fmt.Sprintf(`query{user(id:%q){id %s{%s}}}`, h.UUID(actor), field, fields), nil)
					s2Allow(t, r, "user")
				})
			}
			t.Run("deleteSession", func(t *testing.T) {
				before := s2Snapshot(t, f)
				r := s2Call(t, f, "guard-delete-other-session", actor, fmt.Sprintf(`mutation{deleteAll(input:[{type:userSession,id:%q}])}`, f.sessions["b"]), nil)
				// Existing target-subset semantics: no-op success for unauthorized foreign Session is expected.
				s2Allow(t, r, "deleteAll")
				if pa {
					assert.Equal(t, "0", s2Scalar(t, f, `SELECT count(*)::text FROM auth_user_sessions WHERE id=$1`, f.sessions["b"]))
					tok, e := h.App().AuthHandler.CreateSession(context.Background(), "D02-S2-B replacement B Session", h.UUID("b"))
					require.NoError(t, e)
					f.tokens["b"], e = tok.Encode(h.App().SessionKeyring.Sign)
					require.NoError(t, e)
					f.sessions["b"] = s2Scalar(t, f, `SELECT id::text FROM auth_user_sessions WHERE user_id=$1`, h.UUID("b"))
				} else {
					assert.Equal(t, before, s2Snapshot(t, f))
				}
			})
			t.Run("AuthSubject-add-delete", func(t *testing.T) {
				sub := "s2-subject-" + actor
				input := fmt.Sprintf(`{userID:%q,providerID:"s2-test",subjectID:%q}`, h.UUID("b"), sub)
				before := s2Snapshot(t, f)
				r := s2Call(t, f, "guard-add-foreign-AuthSubject", actor, `mutation{addAuthSubject(input:`+input+`)}`, nil)
				if pa {
					s2Allow(t, r, "addAuthSubject")
					assert.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM auth_subjects WHERE user_id=$1 AND subject_id=$2`, h.UUID("b"), sub))
				} else {
					s2Deny(t, r)
					assert.Equal(t, before, s2Snapshot(t, f))
					s2Exec(t, f, `INSERT INTO auth_subjects(provider_id,subject_id,user_id) VALUES('s2-test',$1,$2)`, sub, h.UUID("b"))
				}
				before = s2Snapshot(t, f)
				r = s2Call(t, f, "guard-delete-foreign-AuthSubject", actor, `mutation{deleteAuthSubject(input:`+input+`)}`, nil)
				if pa {
					s2Allow(t, r, "deleteAuthSubject")
					assert.Equal(t, "0", s2Scalar(t, f, `SELECT count(*)::text FROM auth_subjects WHERE user_id=$1 AND subject_id=$2`, h.UUID("b"), sub))
				} else {
					s2Deny(t, r)
					assert.Equal(t, before, s2Snapshot(t, f))
				}
				own := fmt.Sprintf(`{userID:%q,providerID:"s2-test",subjectID:%q}`, h.UUID(actor), "s2-own-"+actor)
				r = s2Call(t, f, "guard-add-own-AuthSubject", actor, `mutation{addAuthSubject(input:`+own+`)}`, nil)
				s2Allow(t, r, "addAuthSubject")
				assert.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM auth_subjects WHERE user_id=$1 AND subject_id=$2`, h.UUID(actor), "s2-own-"+actor))
				before = s2Snapshot(t, f)
				r = s2Call(t, f, "guard-delete-own-AuthSubject", actor, `mutation{deleteAuthSubject(input:`+own+`)}`, nil)
				if pa {
					s2Allow(t, r, "deleteAuthSubject")
				} else {
					s2Deny(t, r)
					assert.Equal(t, before, s2Snapshot(t, f))
				}
			})
			t.Run("BasicAuth-create-update", func(t *testing.T) {
				before := s2Snapshot(t, f)
				r := s2Call(t, f, "guard-create-other-BasicAuth", actor, fmt.Sprintf(`mutation{createBasicAuth(input:{userID:%q,username:%q,password:"S2-Synthetic-Password-Only-814!"})}`, h.UUID("b"), "s2-basic-"+actor), nil)
				if pa {
					s2Allow(t, r, "createBasicAuth")
					assert.Equal(t, "s2-basic-"+actor, s2Scalar(t, f, `SELECT username FROM auth_basic_users WHERE user_id=$1`, h.UUID("b")))
				} else {
					s2Deny(t, r)
					assert.Equal(t, before, s2Snapshot(t, f))
				}
				before = s2Snapshot(t, f)
				oldHash := s2Scalar(t, f, `SELECT coalesce((SELECT md5(password_hash) FROM auth_basic_users WHERE user_id=$1),'absent')`, h.UUID("b"))
				r = s2Call(t, f, "guard-update-other-BasicAuth", actor, fmt.Sprintf(`mutation{updateBasicAuth(input:{userID:%q,password:"S2-Synthetic-Password-Only-915!"})}`, h.UUID("b")), nil)
				if pa {
					s2Allow(t, r, "updateBasicAuth")
					newHash := s2Scalar(t, f, `SELECT md5(password_hash) FROM auth_basic_users WHERE user_id=$1`, h.UUID("b"))
					assert.NotEqual(t, oldHash, newHash)
					s2Save(t, "password-hash-changed", map[string]any{"changed": oldHash != newHash, "credential_bytes_exported": false})
				} else {
					s2Deny(t, r)
					assert.Equal(t, before, s2Snapshot(t, f))
				}
				// Remove only this task-created synthetic BasicAuth target between independent actors.
				s2Exec(t, f, `DELETE FROM auth_basic_users WHERE user_id=$1`, h.UUID("b"))
				s2Exec(t, f, `DELETE FROM auth_subjects WHERE provider_id='basic' AND user_id=$1`, h.UUID("b"))
			})
			t.Run("end-other-self-Sessions", func(t *testing.T) {
				_, e := h.App().AuthHandler.CreateSession(context.Background(), "D02-S2-B extra self Session", h.UUID(actor))
				require.NoError(t, e)
				otherBefore := s2Rows(t, f, `SELECT id,user_id FROM auth_user_sessions WHERE user_id<>$1`, h.UUID(actor))
				r := s2Call(t, f, "guard-endAll-other-self-sessions", actor, `mutation{endAllAuthSessionsByCurrentUser}`, nil)
				s2Allow(t, r, "endAllAuthSessionsByCurrentUser")
				assert.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM auth_user_sessions WHERE user_id=$1`, h.UUID(actor)))
				assert.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM auth_user_sessions WHERE id=$1`, f.sessions[actor]))
				assert.Equal(t, otherBefore, s2Rows(t, f, `SELECT id,user_id FROM auth_user_sessions WHERE user_id<>$1`, h.UUID(actor)))
			})
			t.Run("linkAccount", func(t *testing.T) {
				subject := "s2-link-" + actor
				link, e := h.App().AuthLinkStore.AuthLinkURL(permission.SystemContext(h.Config().Context(t.Context()), "D02S2BFixture"), "s2-link-test", subject, authlink.Metadata{UserDetails: "Synthetic local proof"})
				require.NoError(t, e)
				u, e := url.Parse(link)
				require.NoError(t, e)
				token := u.Query().Get("authLinkToken")
				require.NotEmpty(t, token)
				r := s2Call(t, f, "guard-linkAccount-signed-proof", actor, `mutation Link($token:ID!){linkAccount(token:$token)}`, map[string]any{"token": token})
				s2Allow(t, r, "linkAccount")
				assert.Equal(t, h.UUID(actor), s2Scalar(t, f, `SELECT user_id::text FROM auth_subjects WHERE provider_id='s2-link-test' AND subject_id=$1`, subject))
				before := s2Snapshot(t, f)
				r = s2Call(t, f, "guard-linkAccount-replay", actor, `mutation Link($token:ID!){linkAccount(token:$token)}`, map[string]any{"token": token})
				s2Deny(t, r)
				assert.Equal(t, before, s2Snapshot(t, f))
			})
		})
	}
	t.Run("BasicAuth-owner-self", func(t *testing.T) {
		r := s2Call(t, f, "BasicAuth-self-create", "b", fmt.Sprintf(`mutation{createBasicAuth(input:{userID:%q,username:"s2-basic-owner",password:"S2-Synthetic-Password-Only-814!"})}`, h.UUID("b")), nil)
		s2Allow(t, r, "createBasicAuth")
		before := s2Snapshot(t, f)
		r = s2Call(t, f, "BasicAuth-self-update-without-old-password", "b", fmt.Sprintf(`mutation{updateBasicAuth(input:{userID:%q,password:"S2-Synthetic-Password-Only-915!"})}`, h.UUID("b")), nil)
		assert.NotEmpty(t, r.Errors)
		assert.Contains(t, string(r.Raw), "Previous password required")
		assert.Equal(t, before, s2Snapshot(t, f))
		r = s2Call(t, f, "BasicAuth-self-update-with-proof", "b", fmt.Sprintf(`mutation{updateBasicAuth(input:{userID:%q,oldPassword:"S2-Synthetic-Password-Only-814!",password:"S2-Synthetic-Password-Only-915!"})}`, h.UUID("b")), nil)
		s2Allow(t, r, "updateBasicAuth")
	})
}
