package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/app"
	"github.com/target/goalert/notification"
	"github.com/target/goalert/test/smoke/harness"
)

const c9CMFields = `id name type private disabled pending statusUpdates value formattedValue dest{type args values{fieldID value} displayInfo{... on DestinationDisplayInfo{text linkURL iconURL iconAltText} ... on DestinationDisplayInfoError{error}}}`

func c9Harness(t *testing.T, hooks ...func(*app.Config)) *harness.Harness {
	t.Helper()
	h := harness.NewStoppedHarness(t, stepParentOrganizationSQL+`INSERT INTO users(id,name,email,role) VALUES({{uuid "c9-peer"}},'C9 Peer','','user');`, nil, "")
	t.Cleanup(h.Close)
	h.StartWithAppCfgHook(func(cfg *app.Config) {
		for _, hook := range hooks {
			hook(cfg)
		}
	})
	pauseStepOrganizationEngine(t, h)
	// Both are real normal Organizations. The default legacy human Admin is
	// assigned to Org A by the harness, independently of its global role.
	h.GraphQLToken(harness.DefaultGraphQLAdminUserID)
	_, err := h.App().DB().Exec(`UPDATE user_organization_assignments SET effective_organization_id=$1,effective_normal_organization_id=$1 WHERE user_id=$2`, h.UUID("org-b"), h.UUID("user-other"))
	require.NoError(t, err)
	return h
}

func c9Query(t *testing.T, h *harness.Harness, actor, query string) *stepOrganizationResponse {
	t.Helper()
	if actor != harness.DefaultGraphQLAdminUserID {
		actor = h.UUID(actor)
	}
	return stepOrganizationPost(t, h, map[string]any{"query": query}, h.GraphQLToken(actor), false)
}

func c9InsertCM(t *testing.T, h *harness.Harness, name, owner, typ, field, raw string, private bool) string {
	t.Helper()
	dest, err := json.Marshal(map[string]any{"Type": typ, "Args": map[string]string{field: raw}})
	require.NoError(t, err)
	id := h.UUID(name)
	_, err = h.App().DB().Exec(`INSERT INTO user_contact_methods(id,user_id,name,dest,private,disabled) VALUES($1,$2,$3,$4,$5,false)`, id, h.UUID(owner), name, dest, private)
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,0)`, h.UUID(name+"-rule"), h.UUID(owner), id)
	require.NoError(t, err)
	return id
}

func TestC9ContactPrivacyMatrix(t *testing.T) {
	h := c9Harness(t)
	for _, dst := range []struct{ typ, field, raw string }{
		{"builtin-smtp-email", "email_address", "c9-private-leak@example.invalid"},
		{"builtin-twilio-sms", "phone_number", "+15551234567"},
		{"builtin-webhook", "webhook_url", "https://example.invalid/private/c9-super-secret-token"},
	} {
		for _, private := range []bool{false, true} {
			raw := fmt.Sprint("c9-", private, "-") + dst.raw
			switch dst.field {
			case "phone_number":
				raw = dst.raw
				if private {
					raw = "+15551234568"
				}
			case "webhook_url":
				raw = dst.raw + fmt.Sprint(private)
			}
			id := c9InsertCM(t, h, fmt.Sprintf("c9-%s-%t", dst.typ, private), "user-a", dst.typ, dst.field, raw, private)
			for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN"} {
				_, err := h.App().DB().Exec(`UPDATE user_organization_assignments SET organization_role=$1 WHERE user_id=$2`, role, h.UUID("c9-peer"))
				require.NoError(t, err)
				for _, actor := range []string{"user-a", "c9-peer", harness.DefaultGraphQLAdminUserID, "user-other"} {
					t.Run(fmt.Sprintf("%s/%t/%s/%s", dst.typ, private, role, actor), func(t *testing.T) {
						for _, query := range []string{
							fmt.Sprintf(`{userContactMethod(id:%q){%s}}`, id, c9CMFields),
							fmt.Sprintf(`{user(id:%q){contactMethods{%s} notificationRules{contactMethodID contactMethod{%s}}}}`, h.UUID("user-a"), c9CMFields, c9CMFields),
						} {
							resp := c9Query(t, h, actor, query)
							encoded, err := json.Marshal(resp)
							require.NoError(t, err)
							canRaw := actor == "user-a" || (!private && actor != "user-other")
							if canRaw {
								require.Empty(t, resp.Errors)
								require.Contains(t, string(resp.Data), raw)
							} else {
								require.NotContains(t, string(encoded), raw)
								if actor == "user-other" {
									require.NotContains(t, string(resp.Data), id)
								}
							}
							if private && actor != "user-a" && actor != "user-other" {
								require.Empty(t, resp.Errors)
								require.Contains(t, string(resp.Data), id, "safe administrative metadata remains available")
							}
						}
						compat := map[string]string{"builtin-smtp-email": "EMAIL", "builtin-twilio-sms": "SMS", "builtin-webhook": "WEBHOOK"}[dst.typ]
						predicates := []string{
							fmt.Sprintf(`dest:{type:%q,args:{%s:%q}}`, dst.typ, dst.field, raw),
							fmt.Sprintf(`CMType:%s,CMValue:%q`, compat, raw),
						}
						if dst.field == "phone_number" {
							predicates = append(predicates, fmt.Sprintf(`CMValue:%q`, raw))
						}
						for _, predicate := range predicates {
							resp := c9Query(t, h, actor, `{users(input:{`+predicate+`}){nodes{id}}}`)
							require.Empty(t, resp.Errors)
							if actor == "user-other" || (private && actor != "user-a") {
								require.NotContains(t, string(resp.Data), h.UUID("user-a"))
							} else {
								require.Contains(t, string(resp.Data), h.UUID("user-a"))
							}
						}
					})
				}
			}
		}
	}
}

func TestC9PrivateFlagMutationAtomicity(t *testing.T) {
	h := c9Harness(t)
	id := c9InsertCM(t, h, "c9-mutation", "user-a", "builtin-smtp-email", "email_address", "c9-mutation-secret@example.invalid", true)
	for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN"} {
		_, err := h.App().DB().Exec(`UPDATE user_organization_assignments SET organization_role=$1 WHERE user_id=$2`, role, h.UUID("c9-peer"))
		require.NoError(t, err)
		for _, actor := range []string{"c9-peer", harness.DefaultGraphQLAdminUserID, "user-other"} {
			var before, after string
			require.NoError(t, h.App().DB().QueryRow(`SELECT (to_jsonb(c)||jsonb_build_object('xmin',xmin::text))::text FROM user_contact_methods c WHERE id=$1`, id).Scan(&before))
			resp := c9Query(t, h, actor, fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,name:"bypass",private:false})}`, id))
			require.NotEmpty(t, resp.Errors)
			require.NoError(t, h.App().DB().QueryRow(`SELECT (to_jsonb(c)||jsonb_build_object('xmin',xmin::text))::text FROM user_contact_methods c WHERE id=$1`, id).Scan(&after))
			require.Equal(t, before, after)
		}
	}
	// Existing safe legacy Admin metadata mutation is retained.
	require.Empty(t, c9Query(t, h, harness.DefaultGraphQLAdminUserID, fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,name:"safe admin label"})}`, id)).Errors)
	for _, private := range []bool{false, true, false} {
		require.Empty(t, c9Query(t, h, "user-a", fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,private:%t})}`, id, private)).Errors)
		var stored bool
		require.NoError(t, h.App().DB().QueryRow(`SELECT private FROM user_contact_methods WHERE id=$1`, id).Scan(&stored))
		require.Equal(t, private, stored)
	}
}

func TestC9DiagnosticStatusPersistence(t *testing.T) {
	h := c9Harness(t)
	for _, private := range []bool{false, true} {
		id := c9InsertCM(t, h, fmt.Sprint("c9-diagnostic-", private), "user-a", "builtin-smtp-email", "email_address", "c9-status-secret@example.invalid"+fmt.Sprint(private), private)
		msgID := h.UUID(fmt.Sprint("c9-message-", private))
		_, err := h.App().DB().Exec(`INSERT INTO outgoing_messages(id,message_type,contact_method_id,user_id) VALUES($1,'test_notification',$2,$3)`, msgID, id, h.UUID("user-a"))
		require.NoError(t, err)
		_, err = h.App().DB().Exec(`UPDATE user_contact_methods SET last_test_verify_at=(SELECT created_at FROM outgoing_messages WHERE id=$1) WHERE id=$2`, msgID, id)
		require.NoError(t, err)
		err = h.App().Engine.SetSendResult(context.Background(), &notification.SendResult{ID: msgID, Status: notification.Status{State: notification.StateFailedPerm, Details: "failed delivery to c9-status-secret@example.invalid"}})
		require.NoError(t, err)
		var details string
		require.NoError(t, h.App().DB().QueryRow(`SELECT status_details FROM outgoing_messages WHERE id=$1`, msgID).Scan(&details))
		require.NotContains(t, details, "c9-status-secret")
		// Owners retain ordinary diagnostic access only if existing policy grants
		// it; Admin is still bound by the same no-raw diagnostic rule.
		for _, actor := range []string{harness.DefaultGraphQLAdminUserID} {
			for _, query := range []string{`{messageLogs{nodes{id destination status providerID}}}`, `{debugMessages(input:{}){id destination status}}`} {
				resp := c9Query(t, h, actor, query)
				require.Empty(t, resp.Errors)
				require.NotContains(t, string(resp.Data), "c9-status-secret")
				require.Contains(t, string(resp.Data), msgID)
			}
		}
		for _, actor := range []string{"user-a", harness.DefaultGraphQLAdminUserID} {
			resp := c9Query(t, h, actor, fmt.Sprintf(`{messageStatusHistory(id:%q){status details timestamp}}`, msgID))
			require.Empty(t, resp.Errors)
			require.NotContains(t, string(resp.Data), "c9-status-secret")
		}
		// A legacy persisted value is also sanitized when read; C9 does not
		// rewrite historical rows or add a data migration.
		_, err = h.App().DB().Exec(`UPDATE outgoing_messages SET status_details='legacy c9-status-secret@example.invalid' WHERE id=$1`, msgID)
		require.NoError(t, err)
		_, err = h.App().DB().Exec(`UPDATE message_status_history SET status_details='legacy c9-status-secret@example.invalid' WHERE message_id=$1`, msgID)
		require.NoError(t, err)
		for _, actor := range []string{"user-a", harness.DefaultGraphQLAdminUserID} {
			for _, query := range []string{fmt.Sprintf(`{messageStatusHistory(id:%q){status details timestamp}}`, msgID), fmt.Sprintf(`{userContactMethod(id:%q){lastTestMessageState{details}}}`, id)} {
				resp := c9Query(t, h, actor, query)
				require.Empty(t, resp.Errors)
				require.NotContains(t, string(resp.Data), "c9-status-secret")
			}
		}
		_, err = h.App().DB().Exec(`UPDATE users SET role='admin' WHERE id=$1`, h.UUID("user-a"))
		require.NoError(t, err)
		for _, query := range []string{`{messageLogs{nodes{id destination status providerID retryCount createdAt updatedAt}}}`, `{debugMessages(input:{}){id destination status}}`} {
			resp := c9Query(t, h, "user-a", query)
			require.Empty(t, resp.Errors)
			require.NotContains(t, string(resp.Data), "c9-status-secret")
			require.Contains(t, string(resp.Data), msgID)
		}
	}
}
