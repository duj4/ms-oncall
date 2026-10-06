package smoke

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/expflag"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func TestSendSignalOrganizationDenialNoDelivery(t *testing.T) {
	const foreignSQL = `
		INSERT INTO organizations(id,classification,display_name,canonical_name)
		VALUES({{uuid "signal-org-b"}},'NORMAL','C6 Foreign Organization','c6-signal-foreign');
		INSERT INTO normal_organizations(organization_id,organization_classification,corporate_mapping_key,iana_time_zone)
		VALUES({{uuid "signal-org-b"}},'NORMAL','c6-signal-foreign','Etc/UTC');
		INSERT INTO escalation_policies(id,name,organization_id)
		VALUES({{uuid "signal-ep-b"}},'C6 Foreign Policy',{{uuid "signal-org-b"}});
		INSERT INTO services(id,name,escalation_policy_id,organization_id)
		VALUES({{uuid "signal-svc-b"}},'C6 Foreign Service',{{uuid "signal-ep-b"}},{{uuid "signal-org-b"}});
	`
	h := harness.NewHarnessWithFlags(t, signalTestSQL+foreignSQL, "", expflag.FlagSet{expflag.UnivKeys})
	defer h.Close()
	channel := h.Slack().Channel("c6-denied-signals")
	h.GraphQLToken(harness.DefaultGraphQLAdminUserID)
	h.Trigger()
	state := func() string {
		t.Helper()
		var s string
		require.NoError(t, h.App().DB().QueryRow(`
			SELECT jsonb_build_object(
				'channels',(SELECT COALESCE(jsonb_agg(to_jsonb(n)||jsonb_build_object('row_version',n.xmin::text) ORDER BY n.id),'[]') FROM notification_channels n),
				'signals',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY s.id),'[]') FROM pending_signals s),
				'jobs',(SELECT COALESCE(jsonb_agg(to_jsonb(j) ORDER BY j.id),'[]') FROM river_job j WHERE queue='engine-signal-mgr' AND args->>'ServiceID' IN ($1,$2)),
				'outgoing',(SELECT COALESCE(jsonb_agg(to_jsonb(o) ORDER BY o.id),'[]') FROM outgoing_messages o)
			)::text
		`, h.UUID("svc"), h.UUID("signal-svc-b")).Scan(&s))
		return s
	}
	for _, serviceID := range []string{h.UUID("signal-svc-b"), h.UUID("signal-missing-service")} {
		before := state()
		response := scopedSmokeQueryExpectNoRows(t, h, fmt.Sprintf(`mutation{sendSignal(input:{serviceID:%q,dest:{type:"builtin-slack-channel",args:{slack_channel_id:%q}},params:{message:"C6 denied signal"}})}`, serviceID, channel.ID()))
		require.Len(t, response.Errors, 1)
		h.Trigger()
		require.Equal(t, before, state(), "denied human requests must leave all destination/signal/job/delivery state unchanged")
		h.Slack().WaitAndAssert() // mock provider asserts zero unconsumed messages after Engine cycles.
	}
	before := state()
	ctx := permission.UserSourceContext(context.Background(), harness.DefaultGraphQLAdminUserID, permission.RoleAdmin,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()})
	app := &graphqlapp.App{DB: h.App().DB(), ServiceStore: h.App().ServiceStore, NCStore: h.App().NCStore}
	ok, err := app.Mutation().SendSignal(expflag.Context(ctx, expflag.FlagSet{expflag.UnivKeys}), graphql2.SendSignalInput{
		ServiceID: h.UUID("svc"), Dest: &gadb.DestV1{Type: "builtin-slack-channel", Args: map[string]string{"slack_channel_id": channel.ID()}},
	})
	require.False(t, ok)
	require.True(t, permission.IsPermissionError(err))
	h.Trigger()
	require.Equal(t, before, state(), "missing human authority must also produce zero side effects")
	h.Slack().WaitAndAssert()
}
