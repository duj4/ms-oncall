package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/user"
)

func c9HumanContext(t *testing.T, h *harness.Harness, actor string) (context.Context, *uuid.UUID) {
	t.Helper()
	if actor != harness.DefaultGraphQLAdminUserID {
		actor = h.UUID(actor)
	}
	var role permission.Role
	require.NoError(t, h.App().DB().QueryRow(`SELECT role FROM users WHERE id=$1`, actor).Scan(&role))
	sessionID := uuid.NewString()
	ctx := permission.UserSourceContext(context.Background(), actor, role, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: sessionID})
	req, err := auth.NewRequester(actor, sessionID)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, req)
	constructor, err := executioncontext.NewHumanExecutionContextConstructor(h.App().OrganizationStore)
	require.NoError(t, err)
	authority, err := constructor.Construct(ctx)
	require.NoError(t, err)
	org, ok := authority.EffectiveOrganizationID()
	require.True(t, ok)
	return h.Config().Context(executioncontext.WithExecutionContext(ctx, authority)), &org
}

func TestC9StoreAndNonDataloaderParity(t *testing.T) {
	h := c9Harness(t)
	direct := graphqlapp.App{DB: h.App().DB(), CMStore: h.App().ContactMethodStore}
	for _, private := range []bool{false, true} {
		raw := fmt.Sprintf("c9-fallback-%t@example.invalid", private)
		id := c9InsertCM(t, h, fmt.Sprintf("c9-fallback-%t", private), "user-a", "builtin-smtp-email", "email_address", raw, private)
		for _, actor := range []string{"user-a", "c9-peer", harness.DefaultGraphQLAdminUserID, "user-other"} {
			ctx, org := c9HumanContext(t, h, actor)
			cm, err := direct.FindOneCM(ctx, uuid.MustParse(id))
			require.NoError(t, err)
			many, err := h.App().ContactMethodStore.FindMany(ctx, h.App().DB(), []string{id}, org)
			require.NoError(t, err)
			list, _, err := h.App().ContactMethodStore.FindAll(ctx, h.App().DB(), h.UUID("user-a"), org)
			require.NoError(t, err)
			if actor == "user-other" {
				require.Nil(t, cm)
				require.Empty(t, many)
				require.Empty(t, list)
				continue
			}
			require.NotNil(t, cm)
			require.Len(t, many, 1)
			require.Equal(t, cm.Dest, many[0].Dest)
			if private && actor != "user-a" {
				require.Empty(t, cm.Dest.Args)
			} else {
				require.Equal(t, raw, cm.Dest.Arg("email_address"))
			}
			for _, listed := range list {
				if listed.ID == cm.ID {
					require.Equal(t, cm.Dest, listed.Dest)
				}
			}
		}
		ctx, _ := c9HumanContext(t, h, "user-a")
		_, err := h.App().ContactMethodStore.FindOne(ctx, h.App().DB(), uuid.MustParse(id))
		require.Error(t, err, "admitted human Store reads require explicit application-bound Organization")
		cm, err := h.App().ContactMethodStore.FindOne(permission.SystemContext(context.Background(), "C9Delivery"), h.App().DB(), uuid.MustParse(id))
		require.NoError(t, err)
		require.Equal(t, raw, cm.Dest.Arg("email_address"))
		users, err := h.App().UserStore.Search(permission.SystemContext(context.Background(), "C9Reverse"), &user.SearchOptions{DestType: cm.Dest.Type, DestArgs: cm.Dest.Args})
		require.NoError(t, err)
		require.Len(t, users, 1)
		require.Equal(t, h.UUID("user-a"), users[0].ID)
	}
	foreign := c9InsertCM(t, h, "c9-foreign-batch", "user-other", "builtin-smtp-email", "email_address", "c9-orgb-secret@example.invalid", false)
	local := c9InsertCM(t, h, "c9-local-batch", "user-a", "builtin-smtp-email", "email_address", "c9-orga@example.invalid", true)
	resp := c9Query(t, h, "user-a", fmt.Sprintf(`{local:userContactMethod(id:%q){%s} foreign:userContactMethod(id:%q){%s}}`, local, c9CMFields, foreign, c9CMFields))
	require.Empty(t, resp.Errors)
	require.Contains(t, string(resp.Data), local)
	require.NotContains(t, string(resp.Data), foreign)
	require.NotContains(t, string(resp.Data), "c9-orgb-secret")
	for _, predicate := range []string{`dest:{type:"builtin-smtp-email"}`, `CMType:EMAIL`} {
		resp := c9Query(t, h, "user-other", `{users(input:{`+predicate+`}){nodes{id}}}`)
		// Preserve the legacy type-only argument validation and empty-result
		// behavior; neither path may identify the foreign owner's User.
		require.NotContains(t, string(resp.Data), h.UUID("user-a"))
	}
}

func TestC9PrivacyMutationStoreAndForeignLockBoundary(t *testing.T) {
	h := c9Harness(t)
	id := c9InsertCM(t, h, "c9-store-mutate", "user-a", "builtin-smtp-email", "email_address", "c9-store-mutation-secret@example.invalid", true)
	foreign := c9InsertCM(t, h, "c9-locked-foreign", "user-other", "builtin-smtp-email", "email_address", "c9-locked-secret@example.invalid", false)
	ctx, org := c9HumanContext(t, h, harness.DefaultGraphQLAdminUserID)
	cm, err := h.App().ContactMethodStore.FindOne(permission.SystemContext(context.Background(), "C9Fixture"), h.App().DB(), uuid.MustParse(id))
	require.NoError(t, err)
	cm.Private = false
	cm.Name = "attempted direct bypass"
	var before, after string
	require.NoError(t, h.App().DB().QueryRow(`SELECT to_jsonb(c)::text FROM user_contact_methods c WHERE id=$1`, id).Scan(&before))
	tx, err := h.App().DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	require.Error(t, h.App().ContactMethodStore.Update(ctx, tx, cm, org))
	require.NoError(t, tx.Rollback())
	require.NoError(t, h.App().DB().QueryRow(`SELECT to_jsonb(c)::text FROM user_contact_methods c WHERE id=$1`, id).Scan(&after))
	require.Equal(t, before, after)
	foreignLock, err := h.App().DB().BeginTx(context.Background(), nil)
	require.NoError(t, err)
	defer foreignLock.Rollback()
	_, err = foreignLock.Exec(`SELECT 1 FROM user_contact_methods WHERE id=$1 FOR UPDATE`, foreign)
	require.NoError(t, err)
	lookupCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	cm, err = h.App().ContactMethodStore.FindOneForUpdate(lookupCtx, h.App().DB(), uuid.MustParse(foreign), org)
	require.ErrorIs(t, err, sql.ErrNoRows, "Organization denial must precede the foreign row lock")
	require.Nil(t, cm)
}

func TestC9CreateDefaultsAndOwnerVerificationDelivery(t *testing.T) {
	capture := new(c9LogCapture)
	h := c9Harness(t, capture.attach)
	webhookMessages := make(chan map[string]any, 10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]any
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		webhookMessages <- msg
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	for _, flag := range []string{"", "private:false,", "private:true,"} {
		name := "c9-create-" + strconv.Itoa(len(flag))
		raw := server.URL + "/private/c9-owner-secret-token-" + strconv.Itoa(len(flag))
		query := fmt.Sprintf(`mutation{createUserContactMethod(input:{userID:%q,name:%q,%sdest:{type:"builtin-webhook",args:{webhook_url:%q}},newUserNotificationRule:{delayMinutes:0}}){%s}}`, h.UUID("user-a"), name, flag, raw, c9CMFields)
		resp := c9Query(t, h, "user-a", query)
		require.Empty(t, resp.Errors)
		require.Contains(t, string(resp.Data), raw)
		var result struct {
			CreateUserContactMethod struct {
				ID      string
				Private bool
			}
		}
		require.NoError(t, json.Unmarshal(resp.Data, &result))
		id := result.CreateUserContactMethod.ID
		var stored bool
		require.NoError(t, h.App().DB().QueryRow(`SELECT private FROM user_contact_methods WHERE id=$1`, id).Scan(&stored))
		require.Equal(t, flag == "private:true,", stored)
		require.Equal(t, stored, result.CreateUserContactMethod.Private)
		// Existing owner consent gates apply to tests and verification for both
		// flags, with no outgoing row or privacy mutation on denial.
		for _, actor := range []string{"c9-peer", harness.DefaultGraphQLAdminUserID, "user-other"} {
			for _, operation := range []string{fmt.Sprintf(`testContactMethod(id:%q)`, id), fmt.Sprintf(`sendContactMethodVerification(input:{contactMethodID:%q})`, id), fmt.Sprintf(`verifyContactMethod(input:{contactMethodID:%q,code:123456})`, id)} {
				// Existing Admin verification authority is retained. Send Test
				// remains owner-only, and arbitrary verification codes still fail.
				if actor == harness.DefaultGraphQLAdminUserID && strings.HasPrefix(operation, "sendContactMethodVerification") {
					continue
				}
				resp := c9Query(t, h, actor, `mutation{`+operation+`}`)
				require.NotEmpty(t, resp.Errors)
				require.NotContains(t, fmt.Sprint(resp), "c9-owner-secret-token")
			}
		}
		var before int
		require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM outgoing_messages WHERE contact_method_id=$1`, id).Scan(&before))
		require.Zero(t, before)
		require.Empty(t, c9Query(t, h, "user-a", fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,name:"owner label",enableStatusUpdates:true})}`, id)).Errors)
		require.Empty(t, c9Query(t, h, "user-a", fmt.Sprintf(`mutation{sendContactMethodVerification(input:{contactMethodID:%q})}`, id)).Errors)
		require.NoError(t, h.App().Engine.Resume(context.Background()))
		h.Trigger()
		var verification map[string]any
		select {
		case verification = <-webhookMessages:
		case <-time.After(10 * time.Second):
			t.Fatal("private flag prevented verification delivery")
		}
		require.Equal(t, "Verification", verification["Type"])
		code, err := strconv.Atoi(fmt.Sprint(verification["Code"]))
		require.NoError(t, err)
		pauseStepOrganizationEngine(t, h)
		require.Empty(t, c9Query(t, h, "user-a", fmt.Sprintf(`mutation{verifyContactMethod(input:{contactMethodID:%q,code:%d})}`, id, code)).Errors)
		var disabled, pending bool
		require.NoError(t, h.App().DB().QueryRow(`SELECT disabled,pending FROM user_contact_methods WHERE id=$1`, id).Scan(&disabled, &pending))
		require.False(t, disabled)
		require.False(t, pending)
		// Respect the existing one-minute rate limit.
		h.FastForward(2 * time.Minute)
		require.Empty(t, c9Query(t, h, "user-a", fmt.Sprintf(`mutation{testContactMethod(id:%q)}`, id)).Errors)
		require.NoError(t, h.App().Engine.Resume(context.Background()))
		h.Trigger()
		select {
		case testMsg := <-webhookMessages:
			require.Equal(t, "Test", testMsg["Type"])
		case <-time.After(10 * time.Second):
			t.Fatal("private flag prevented test delivery")
		}
		pauseStepOrganizationEngine(t, h)
	}
	// An existing authorized Admin may create for another same-Org User. Its
	// response is metadata-only for private=true, then the owner sees raw.
	raw := server.URL + "/private/c9-admin-create-secret"
	resp := c9Query(t, h, harness.DefaultGraphQLAdminUserID, fmt.Sprintf(`mutation{createUserContactMethod(input:{userID:%q,name:"admin created",private:true,dest:{type:"builtin-webhook",args:{webhook_url:%q}}}){%s}}`, h.UUID("user-a"), raw, c9CMFields))
	require.Empty(t, resp.Errors)
	require.NotContains(t, string(resp.Data), raw)
	var result struct{ CreateUserContactMethod struct{ ID string } }
	require.NoError(t, json.Unmarshal(resp.Data, &result))
	owner := c9Query(t, h, "user-a", fmt.Sprintf(`{userContactMethod(id:%q){%s}}`, result.CreateUserContactMethod.ID, c9CMFields))
	require.Empty(t, owner.Errors)
	require.Contains(t, string(owner.Data), raw)
	resp = c9Query(t, h, harness.DefaultGraphQLAdminUserID, fmt.Sprintf(`mutation{createUserContactMethod(input:{userID:%q,name:"foreign create",dest:{type:"builtin-webhook",args:{webhook_url:%q}}}){%s}}`, h.UUID("user-other"), raw, c9CMFields))
	require.NotEmpty(t, resp.Errors)
	require.NotContains(t, string(resp.Data), raw)
	require.NotContains(t, capture.snapshot(), "c9-owner-secret-token")
	require.NotContains(t, capture.snapshot(), "c9-admin-create-secret")
}
