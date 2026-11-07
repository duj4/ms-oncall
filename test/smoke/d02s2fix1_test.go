package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/user"
)

func fix1Human(t *testing.T, f *s2Fixture, actor string) context.Context {
	t.Helper()
	role := permission.RoleUser
	if actor == "pam" || actor == "paa" {
		role = permission.RoleAdmin
	}
	ctx := permission.UserSourceContext(t.Context(), f.h.UUID(actor), role,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: f.sessions[actor]})
	req, err := auth.NewRequester(f.h.UUID(actor), f.sessions[actor])
	require.NoError(t, err)
	constructor, err := executioncontext.NewHumanExecutionContextConstructor(f.h.App().OrganizationStore)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, req)
	ec, err := constructor.Construct(ctx)
	require.NoError(t, err)
	return executioncontext.WithExecutionContext(ctx, ec)
}

func TestD02S2Fix1UserIsolation(t *testing.T) {
	f := s2New(t)
	before := s2Snapshot(t, f)
	for _, actor := range []string{"om", "oa"} {
		t.Run(actor, func(t *testing.T) {
			for _, query := range []string{
				`query($id:ID!){profile:user(id:$id){...Profile}} fragment Profile on User{id name email role}`,
				`query($id:ID!){safe:user(id:$id){id onCallSteps{id}} profile:user(id:$id){id name email role}}`,
				`query($id:ID!){profile:user(id:$id){id onCallSteps{id} email @include(if:true)}}`,
			} {
				r := s2Call(t, f, "foreign-profile-and-loader-cache", actor, query, map[string]any{"id": f.h.UUID("b")})
				require.Equal(t, 200, r.Status)
				require.Empty(t, r.Errors)
				require.Equal(t, "null", string(r.Data["profile"]))
				require.NotContains(t, string(r.Raw), "b@example.invalid")
				require.NotContains(t, string(r.Raw), "S2 SYNTHETIC b")
			}
			r := s2Call(t, f, "self-and-home", actor, fmt.Sprintf(`{self:user{id name email role} home:user(id:%q){id name email role}}`, f.h.UUID("aowner")), nil)
			require.Empty(t, r.Errors)
			require.Contains(t, string(r.Raw), f.h.UUID(actor))
			require.Contains(t, string(r.Raw), "aowner@example.invalid")
			r = s2Call(t, f, "foreign-search", actor, `{users(input:{search:"S2 SYNTHETIC b"}){nodes{id name email role}}}`, nil)
			require.Empty(t, r.Errors)
			require.JSONEq(t, `{"nodes":[]}`, string(r.Data["users"]))
			r = s2Call(t, f, "User-destination-field-search", actor,
				`{destinationFieldSearch(input:{destType:"builtin-user",fieldID:"user_id",search:"S2 SYNTHETIC",first:100}){nodes{value label}}}`, nil)
			require.Empty(t, r.Errors)
			require.NotContains(t, string(r.Raw), f.h.UUID("b"))
			require.NotContains(t, string(r.Raw), f.h.UUID("ba"))
			require.Contains(t, string(r.Raw), f.h.UUID("aowner"))

			seen := map[string]bool{}
			var after *string
			for page := 0; ; page++ {
				require.Less(t, page, 5, "pagination must terminate")
				r = s2Call(t, f, "organization-pagination", actor,
					`query($after:String){users(input:{first:2,after:$after,search:"S2 SYNTHETIC"}){nodes{id name email role} pageInfo{endCursor hasNextPage}}}`,
					map[string]any{"after": after})
				require.Empty(t, r.Errors)
				var conn struct {
					Nodes    []struct{ ID, Name, Email, Role string }
					PageInfo struct {
						EndCursor   *string
						HasNextPage bool
					}
				}
				require.NoError(t, json.Unmarshal(r.Data["users"], &conn))
				for _, u := range conn.Nodes {
					require.NotEqual(t, f.h.UUID("b"), u.ID)
					require.NotEqual(t, f.h.UUID("ba"), u.ID)
					require.False(t, seen[u.ID])
					seen[u.ID] = true
				}
				if !conn.PageInfo.HasNextPage {
					break
				}
				require.NotNil(t, conn.PageInfo.EndCursor)
				after = conn.PageInfo.EndCursor
			}
			want := map[string]bool{}
			for _, name := range []string{"om", "oa", "pam", "paa", "aowner", "spare"} {
				want[f.h.UUID(name)] = true
			}
			require.Equal(t, want, seen, "all pages must contain exactly Home Users")

			direct := &graphqlapp.App{DB: f.h.App().DB(), UserStore: f.h.App().UserStore}
			ctx := fix1Human(t, f, actor)
			got, err := direct.FindOneUser(ctx, f.h.UUID("b"))
			require.NoError(t, err)
			require.Nil(t, got, "non-loader path must enforce the same profile boundary")
			foreignHidden := got == nil
			got, err = direct.FindOneUser(ctx, f.h.UUID("aowner"))
			require.NoError(t, err)
			require.Equal(t, f.h.UUID("aowner"), got.ID)
			home := uuid.MustParse(f.h.UUID("s2-org-a"))
			users, err := f.h.App().UserStore.FindManyInOrganization(ctx, []string{f.h.UUID("b"), f.h.UUID(actor)}, home)
			require.NoError(t, err)
			require.Len(t, users, 1)
			require.Equal(t, f.h.UUID(actor), users[0].ID)
			users, err = f.h.App().UserStore.Search(ctx, &user.SearchOptions{OrganizationID: home, Search: "S2 SYNTHETIC b"})
			require.NoError(t, err)
			require.Empty(t, users)
			s2Save(t, "nonloader-and-scoped-store", map[string]any{"actor": actor, "foreign_profile_hidden": foreignHidden, "scoped_search": users})
		})
	}
	for _, actor := range []string{"pam", "paa"} {
		t.Run(actor, func(t *testing.T) {
			r := s2Call(t, f, "PA-global-profile", actor, fmt.Sprintf(`{user(id:%q){id name email role} users(first:100){nodes{id name email role}}}`, f.h.UUID("b")), nil)
			require.Empty(t, r.Errors)
			require.Contains(t, string(r.Data["user"]), "b@example.invalid")
			require.Contains(t, string(r.Data["users"]), f.h.UUID("b"))
			r = s2Call(t, f, "missing-profile", actor, fmt.Sprintf(`{user(id:%q){id name}}`, f.h.UUID("absent")), nil)
			require.Empty(t, r.Errors)
			require.Equal(t, "null", string(r.Data["user"]))
		})
	}
	require.Equal(t, before, s2Snapshot(t, f), "all User reads preserve business state")
}

func TestD02S2Fix1RelatedUserProfiles(t *testing.T) {
	f := s2New(t)
	// A legacy foreign participant is synthetic historical state, not a grant
	// to create new cross-Organization relationships through the application.
	for _, target := range []string{"aowner", "b"} {
		s2Exec(t, f, `INSERT INTO rotations(id,organization_id,name,type,start_time,shift_length,time_zone)
			VALUES($1,$2,$3,'weekly',now(),1,'Asia/Shanghai')`,
			f.h.UUID("fix1-rotation-"+target), f.h.UUID("s2-org-a"), "FIX1 "+target)
		s2Exec(t, f, `INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES($1,$2,$3,0)`,
			f.h.UUID("fix1-part-"+target), f.h.UUID("fix1-rotation-"+target), f.h.UUID(target))
	}
	// Engine processing is paused: seed its actual persisted OnCall output,
	// rather than assuming that an EP action has already produced that output.
	s2Exec(t, f, `INSERT INTO ep_step_on_call_users(user_id,ep_step_id,start_time)
		VALUES($1,$2,now()-interval '1 hour'),($3,$4,now()-interval '1 hour')`,
		f.h.UUID("aowner"), f.h.UUID("step-a-0"), f.h.UUID("b"), f.h.UUID("step-b-0"))
	before := s2Snapshot(t, f)
	for _, actor := range []string{"om", "oa"} {
		t.Run(actor, func(t *testing.T) {
			r := s2Call(t, f, "related-Home-User-positive", actor, fmt.Sprintf(`{rotation(id:%q){users{id name email role}}}`, f.h.UUID("fix1-rotation-aowner")), nil)
			require.Empty(t, r.Errors)
			require.Contains(t, string(r.Raw), "aowner@example.invalid")
			r = s2Call(t, f, "related-Foreign-full-Profile-denied", actor, fmt.Sprintf(`{rotation(id:%q){users{id name email role}}}`, f.h.UUID("fix1-rotation-b")), nil)
			s2Deny(t, r)
			require.NotContains(t, string(r.Raw), "b@example.invalid")
			require.NotContains(t, string(r.Raw), "S2 SYNTHETIC b")
			// Existing scoped OnCall projections never acquire full Profile data.
			r = s2Call(t, f, "existing-OnCall-projections", actor, fmt.Sprintf(`{home:user(id:%q){id onCallSteps{id} onCallOverview{serviceCount} assignedSchedules{id}} foreign:user(id:%q){id onCallSteps{id}}}`, f.h.UUID("aowner"), f.h.UUID("b")), nil)
			require.Empty(t, r.Errors)
			require.Contains(t, string(r.Data["home"]), f.h.UUID("step-a-0"))
			require.JSONEq(t, fmt.Sprintf(`{"id":%q,"onCallSteps":[]}`, f.h.UUID("b")), string(r.Data["foreign"]))
		})
	}
	require.Equal(t, before, s2Snapshot(t, f))
}

func TestD02S2Fix1ContactMethodTargets(t *testing.T) {
	f := s2New(t)
	h := f.h
	immutable := s2Rows(t, f, `SELECT id,user_id,dest,private,disabled,pending FROM user_contact_methods`)
	for _, actor := range []string{"pam", "paa", "b", "om", "oa", "ba"} {
		t.Run("name-only/"+actor, func(t *testing.T) {
			before := s2Snapshot(t, f)
			r := s2Call(t, f, "same-foreign-target-name-only", actor, fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,name:%q})}`, h.UUID("cm-b"), "FIX1 "+actor), nil)
			if actor == "pam" || actor == "paa" || actor == "b" {
				s2Allow(t, r, "updateUserContactMethod")
				require.Equal(t, "FIX1 "+actor, s2Scalar(t, f, `SELECT name FROM user_contact_methods WHERE id=$1`, h.UUID("cm-b")))
				after := s2Snapshot(t, f)
				before["user_contact_methods"] = after["user_contact_methods"]
				require.Equal(t, before, after)
			} else {
				s2Deny(t, r)
				require.Equal(t, before, s2Snapshot(t, f))
			}
			require.Equal(t, immutable, s2Rows(t, f, `SELECT id,user_id,dest,private,disabled,pending FROM user_contact_methods`))
		})
	}
	for _, actor := range []string{"pam", "paa"} {
		for _, fields := range []string{"private:false", "private:true", "enableStatusUpdates:true", "value:\"replacement@example.invalid\""} {
			t.Run(actor+"/"+fields, func(t *testing.T) {
				before := s2Snapshot(t, f)
				r := s2Call(t, f, "foreign-unapproved-field", actor, fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,%s})}`, h.UUID("cm-b"), fields), nil)
				require.NotEmpty(t, r.Errors)
				require.NotContains(t, string(r.Raw), "b@example.invalid")
				require.Equal(t, before, s2Snapshot(t, f))
			})
		}
		t.Run(actor+"/private-raw", func(t *testing.T) {
			r := s2Call(t, f, "foreign-created-private-projection", actor,
				fmt.Sprintf(`mutation{createUserContactMethod(input:{userID:%q,name:"FIX1 private",private:true,type:EMAIL,value:"fix1-private@example.invalid"}){id name private value formattedValue}}`, h.UUID("b")), nil)
			s2Allow(t, r, "createUserContactMethod")
			require.NotContains(t, string(r.Raw), "fix1-private@example.invalid")
			require.Contains(t, string(r.Raw), "Private contact method")
			require.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM user_contact_methods WHERE user_id=$1 AND name='FIX1 private' AND private`, h.UUID("b")))
			// Remove only this synthetic method so the second actor has the same target.
			s2Exec(t, f, `DELETE FROM user_contact_methods WHERE user_id=$1 AND name='FIX1 private'`, h.UUID("b"))
		})
	}
	for _, op := range []string{"missing-user", "missing-cm", "nested-rollback", "invalid-name", "invalid-destination"} {
		t.Run(op, func(t *testing.T) {
			before := s2Snapshot(t, f)
			q := ""
			switch op {
			case "missing-user":
				q = fmt.Sprintf(`mutation{createUserContactMethod(input:{userID:%q,name:"FIX1 missing",type:EMAIL,value:"fix1@example.invalid"}){id}}`, h.UUID("absent"))
			case "missing-cm":
				q = fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,name:"FIX1 missing"})}`, h.UUID("absent"))
			case "nested-rollback":
				q = fmt.Sprintf(`mutation{createUserContactMethod(input:{userID:%q,name:"FIX1 rollback",type:EMAIL,value:"fix1@example.invalid",newUserNotificationRule:{delayMinutes:-1}}){id}}`, h.UUID("b"))
			case "invalid-name":
				q = fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,name:""})}`, h.UUID("cm-b"))
			case "invalid-destination":
				q = fmt.Sprintf(`mutation{createUserContactMethod(input:{userID:%q,name:"FIX1 invalid",type:EMAIL,value:"invalid"}){id}}`, h.UUID("b"))
			}
			r := s2Call(t, f, "target-validation-and-rollback", "pam", q, nil)
			require.NotEmpty(t, r.Errors)
			require.NotContains(t, fmt.Sprint(r.Errors), "GRAPHQL_VALIDATION_FAILED")
			require.Equal(t, before, s2Snapshot(t, f))
		})
	}
	for _, invalid := range []string{"missing-assignment", "default-target"} {
		t.Run(invalid, func(t *testing.T) {
			if invalid == "missing-assignment" {
				s2Exec(t, f, `DELETE FROM user_organization_assignments WHERE user_id=$1`, h.UUID("b"))
			} else {
				s2Exec(t, f, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count)
					VALUES($1,$2,'DEFAULT','NONE','ZERO',now(),'fix1-invalid',0)`, h.UUID("b"), organization.DefaultOrganizationID)
			}
			for _, actor := range []string{"pam", "paa"} {
				before := s2Snapshot(t, f)
				r := s2Call(t, f, "invalid-normal-target", actor, fmt.Sprintf(`mutation{createUserContactMethod(input:{userID:%q,name:"FIX1 invalid target",type:EMAIL,value:"fix1@example.invalid"}){id}}`, h.UUID("b")), nil)
				s2Deny(t, r)
				require.Equal(t, before, s2Snapshot(t, f))
				before = s2Snapshot(t, f)
				r = s2Call(t, f, "invalid-current-CM-owner", actor, fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,name:"FIX1 invalid target"})}`, h.UUID("cm-b")), nil)
				s2Deny(t, r)
				require.Equal(t, before, s2Snapshot(t, f))
			}
		})
	}
}
