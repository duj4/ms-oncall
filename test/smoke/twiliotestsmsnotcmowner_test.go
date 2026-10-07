package smoke

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

// TestTwilioSMSNotCMOwner checks that a test sent from a user who is not the
// owner of the contact method returns an error.
func TestTwilioSMSNotCMOwner(t *testing.T) {
	t.Parallel()

	sqlQuery := `
	insert into users (id, name, email) 
	values 
		({{uuid "user"}}, 'bob', 'joe');
	insert into user_contact_methods (id, user_id, name, type, value) 
	values
	    ({{uuid "cm1"}}, {{uuid "user"}}, 'personal', 'SMS', {{phone "1"}});
`
	h, logs := c9TwilioHarness(t, sqlQuery)

	cm1 := h.UUID("cm1")
	// The original non-owner Admin is admitted to the same normal Organization.
	// A successful scoped lookup distinguishes ownership denial from missing
	// Organization authority or an invisible Contact Method.
	lookup := h.GraphQLQuery2(fmt.Sprintf(`{userContactMethod(id:%q){id}}`, cm1))
	require.Empty(t, lookup.Errors)
	require.Contains(t, string(lookup.Data), cm1)

	g := h.GraphQLQuery2(fmt.Sprintf(`
		mutation {
			testContactMethod(id: "%s")
		}
		`, cm1))
	require.Len(t, g.Errors, 1, "errors returned from GraphQL")
	require.Equal(t, "access denied", g.Errors[0].Message)
	encoded, err := json.Marshal(g)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), h.Phone("1"))

	// The same authenticated Session cannot retain Organization authority after
	// its durable assignment is removed. No System or role-based fallback.
	_, err = h.App().DB().Exec(`DELETE FROM user_organization_assignments WHERE user_id=$1`, harness.DefaultGraphQLAdminUserID)
	require.NoError(t, err)
	missing := h.GraphQLQuery2(fmt.Sprintf(`mutation{testContactMethod(id:%q)}`, cm1))
	require.Len(t, missing.Errors, 1)
	require.Equal(t, "access denied: normal Organization scoped authority is required", missing.Errors[0].Message)
	encoded, err = json.Marshal(missing)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), h.Phone("1"))
	h.Trigger()
	var queued int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM outgoing_messages`).Scan(&queued))
	require.Zero(t, queued, "neither denied request may enqueue delivery")
	require.NotContains(t, logs.snapshot(), h.Phone("1"))
	// Harness cleanup also rejects any unexpected Twilio/SMTP delivery.
}
