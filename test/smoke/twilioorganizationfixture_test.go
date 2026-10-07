package smoke

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

// c9TwilioHarness preserves the historical migration fixture, then assigns its
// ordinary owner after startup has installed the current Organization schema.
// The historical schema does not yet contain the assignment table.
func c9TwilioHarness(t *testing.T, initSQL string) (*harness.Harness, *c9LogCapture) {
	t.Helper()
	h := harness.NewStoppedHarness(t, initSQL, nil, "add-verification-code")
	logs := new(c9LogCapture)
	h.StartWithAppCfgHook(logs.attach)
	t.Cleanup(h.Close)
	c9AssignSmokeMember(t, h, h.UUID("user"))
	return h, logs
}

func c9AssignSmokeMember(t *testing.T, h *harness.Harness, userID string) {
	t.Helper()
	_, err := h.App().DB().Exec(`INSERT INTO user_organization_assignments
(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count)
VALUES($1,$2,'NORMAL',$2,'ORG_MEMBER','EXACTLY_ONE',now(),'smoke-harness-v1',1)`, userID, harness.SmokeOrganizationID)
	require.NoError(t, err)
	t.Log("Installed normal Organization member assignment after historical fixture upgrade")
}

func TestC9RepairBuiltInPrivateDelivery(t *testing.T) {
	for _, typ := range []string{"SMS", "EMAIL"} {
		t.Run(typ, func(t *testing.T) {
			value := `{{phone "1"}}`
			if typ == "EMAIL" {
				value = `{{email "1"}}`
			}
			initSQL := fmt.Sprintf(`INSERT INTO users(id,name,email,role) VALUES
({{uuid "user"}},'owner','','user'),({{uuid "peer"}},'peer','','user');
INSERT INTO user_contact_methods(id,user_id,name,type,value,disabled)
VALUES({{uuid "cm1"}},{{uuid "user"}},'private delivery','%s',%s,%t);`, typ, value, typ == "SMS")
			h, logs := c9TwilioHarness(t, initSQL)
			c9AssignSmokeMember(t, h, h.UUID("peer"))
			id := h.UUID("cm1")
			_, err := h.App().DB().Exec(`UPDATE user_contact_methods SET private=true WHERE id=$1`, id)
			require.NoError(t, err)
			var private bool
			require.NoError(t, h.App().DB().QueryRow(`SELECT private FROM user_contact_methods WHERE id=$1`, id).Scan(&private))
			require.True(t, private)
			raw := h.Phone("1")
			if typ == "EMAIL" {
				raw = h.Email("1")
			}
			query := fmt.Sprintf(`{userContactMethod(id:%q){%s}}`, id, c9CMFields)
			owner := h.GraphQLQueryUserT(t, h.UUID("user"), query)
			require.Empty(t, owner.Errors)
			require.Contains(t, string(owner.Data), raw)
			peer := h.GraphQLQueryUserT(t, h.UUID("peer"), query)
			require.Empty(t, peer.Errors)
			require.Contains(t, string(peer.Data), id)
			require.NotContains(t, string(peer.Data), raw)
			denied := h.GraphQLQueryUserT(t, h.UUID("peer"), fmt.Sprintf(`mutation{testContactMethod(id:%q)}`, id))
			require.Len(t, denied.Errors, 1)
			require.Equal(t, "access denied", denied.Errors[0].Message)
			encoded, err := json.Marshal(denied)
			require.NoError(t, err)
			require.NotContains(t, string(encoded), raw)
			var queued int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM outgoing_messages`).Scan(&queued))
			require.Zero(t, queued)
			if typ == "SMS" {
				resp := h.GraphQLQueryUserT(t, h.UUID("user"), fmt.Sprintf(`mutation{sendContactMethodVerification(input:{contactMethodID:%q})}`, id))
				require.Empty(t, resp.Errors)
				msg := h.Twilio(t).Device(raw).ExpectSMS("verification")
				codeText := strings.Map(func(r rune) rune {
					if r >= '0' && r <= '9' {
						return r
					}
					return -1
				}, msg.Body())
				code, err := strconv.Atoi(codeText)
				require.NoError(t, err)
				resp = h.GraphQLQueryUserT(t, h.UUID("user"), fmt.Sprintf(`mutation{verifyContactMethod(input:{contactMethodID:%q,code:%d})}`, id, code))
				require.Empty(t, resp.Errors)
				h.FastForward(2 * time.Minute)
			}
			resp := h.GraphQLQueryUserT(t, h.UUID("user"), fmt.Sprintf(`mutation{testContactMethod(id:%q)}`, id))
			require.Empty(t, resp.Errors)
			if typ == "SMS" {
				h.Twilio(t).Device(raw).ExpectSMS("test")
			} else {
				h.SMTP().ExpectMessage(raw, "test")
			}
			require.NotContains(t, logs.snapshot(), raw)
		})
	}
}
