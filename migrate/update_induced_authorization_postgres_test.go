package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

func updateNativeHTTP(t *testing.T, ctx context.Context, app *graphqlapp.App, f *updateNativeFixture, mutation bool, confirm *graphql2.DeletionSafetyConfirmationInput) (map[string]json.RawMessage, []json.RawMessage, string) {
	t.Helper()
	typ, field, input := "UpdateEscalationPolicyInput", "previewUpdateEscalationPolicy", any(f.policy)
	switch f.kind {
	case "U02":
		typ, field, input = "UpdateEscalationPolicyStepInput", "previewUpdateEscalationPolicyStep", f.step
	case "U03":
		typ, field, input = "ScheduleTargetInput", "previewUpdateScheduleTarget", f.target
	}
	selection := "{ impactVersion complete canProceed requiresConfirmation root{type id} removed{type id} impacts{change policy relation} }"
	op := "query"
	raw, err := json.Marshal(input)
	require.NoError(t, err)
	var wire map[string]any
	require.NoError(t, json.Unmarshal(raw, &wire))
	switch f.kind {
	case "U01":
		if f.policy.StepIDs != nil {
			wire["stepIDs"] = f.policy.StepIDs
		}
	case "U02":
		if f.step.Actions != nil {
			actions := make([]map[string]any, len(f.step.Actions))
			for n, a := range f.step.Actions {
				actions[n] = map[string]any{"type": a.Type, "args": a.Args}
			}
			wire["actions"] = actions
		}
	case "U03":
		typ, err := f.target.Target.Type.MarshalText()
		require.NoError(t, err)
		wire["target"] = map[string]any{"type": string(typ), "id": f.target.Target.ID}
	}

	if mutation {
		op = "mutation"
		field = strings.TrimPrefix(field, "preview")
		field = strings.ToLower(field[:1]) + field[1:]
		selection = ""
		if confirm != nil {
			wire["confirmation"] = confirm
		}
	}
	query := fmt.Sprintf("%s($input:%s!){result:%s(input:$input)%s}", op, typ, field, selection)
	payload, err := json.Marshal(map[string]any{"query": query, "variables": map[string]any{"input": wire}})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(payload)).WithContext((config.Config{}).Context(ctx))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	var result struct {
		Data   map[string]json.RawMessage
		Errors []json.RawMessage
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	return result.Data, result.Errors, w.Body.String()
}

func TestPostgresUpdateInducedSafetyAuthorizationHTTP(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	app := updateNativeApp(t, permission.SystemContext(ctx, "UpdateInducedSafetyTest"), db)
	for _, kind := range []string{"U01", "U02", "U03"} {
		t.Run(kind, func(t *testing.T) {
			f := newUpdateNativeFixture(t, ctx, db, kind)
			human := previewAdmit(t, ctx, db, f.actor)
			ordinary := *f
			ordinary.nondestructive()
			_, ordinaryErrors, ordinaryBody := updateNativeHTTP(t, human, app, &ordinary, true, nil)
			require.Empty(t, ordinaryErrors, ordinaryBody)
			_, problems, body := updateNativeHTTP(t, human, app, f, false, nil)
			require.Empty(t, problems, body)
			_, problems, body = updateNativeHTTP(t, human, app, f, true, nil)
			require.NotEmpty(t, problems)
			require.Contains(t, body, "DELETION_CONFIRMATION_REQUIRED")
			data, problems, body := updateNativeHTTP(t, human, app, f, false, nil)
			require.Empty(t, problems, body)
			var p graphql2.UpdateDeletionPreview
			require.NoError(t, json.Unmarshal(data["result"], &p))
			require.True(t, p.RequiresConfirmation)
			otherAdmin := previewAdmit(t, ctx, db, f.user)
			_, err := f.mutate(otherAdmin, app, updateNativeConfirmation(&p))
			enforceCode(t, err, ds.DeletionDependencyChanged)
			// An ordinary member sees no impact identities, including the hidden
			// parent/target UUIDs, and the old mutation cannot bypass confirmation.
			enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.user)
			member := previewAdmit(t, ctx, db, f.user)
			_, problems, body = updateNativeHTTP(t, member, app, f, false, nil)
			require.NotEmpty(t, problems)
			require.NotContains(t, body, f.action.String())
			require.NotContains(t, body, f.schedule.String())
			foreign := newEPProfileFixture(t, ctx, db, false)
			foreignHuman := previewAdmit(t, ctx, db, foreign.actor)
			_, problems, body = updateNativeHTTP(t, foreignHuman, app, f, false, nil)
			require.NotEmpty(t, problems)
			require.NotContains(t, body, f.action.String())
			// Reuse the admitted context after persisted privilege revocation.
			enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
			_, err = f.mutate(human, app, updateNativeConfirmation(&p))
			enforceCode(t, err, ds.DeletionUnavailable)
			enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, f.actor)
			fresh := previewAdmit(t, ctx, db, f.actor)
			data, problems, body = updateNativeHTTP(t, fresh, app, f, false, nil)
			require.Empty(t, problems, body)
			require.NoError(t, json.Unmarshal(data["result"], &p))
			_, problems, body = updateNativeHTTP(t, fresh, app, f, true, updateNativeConfirmation(&p))
			require.Empty(t, problems, body)
		})
	}
}

func TestPostgresUpdateInducedSafetyGlobalAuthority(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	system := permission.SystemContext(ctx, "UpdateInducedSafetyTest")
	app := updateNativeApp(t, system, db)
	for _, home := range []string{"foreign_normal", "default"} {
		for _, kind := range []string{"U01", "U02", "U03"} {
			t.Run(home+"/"+kind, func(t *testing.T) {
				f := newUpdateNativeFixture(t, ctx, db, kind)
				actor := newEPProfileFixture(t, ctx, db, false).actor
				enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, actor)
				if home == "default" {
					enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, actor, organization.DefaultOrganizationID)
				}
				human := previewAdmit(t, ctx, db, actor)
				p, err := f.preview(human, app)
				require.NoError(t, err)
				ok, err := f.mutate(human, app, updateNativeConfirmation(p))
				require.NoError(t, err)
				require.True(t, ok)
			})
		}
	}
}
