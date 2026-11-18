package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

func rotationUpdateHTTP(t *testing.T, ctx context.Context, app *graphqlapp.App, input graphql2.UpdateRotationInput, mutation bool) (*graphql2.UpdateDeletionPreview, []json.RawMessage, string) {
	t.Helper()
	op, field, selection := "query", "previewUpdateRotation", "{impactVersion canProceed complete requiresConfirmation root{type id} removed{type id} impacts{change policy relation}}"
	if mutation {
		op, field, selection = "mutation", "updateRotation", ""
	}
	// Preserve explicit empty userIDs: generated Go's omitempty is not a
	// faithful encoding of the wire distinction between absent and clear.
	raw, err := json.Marshal(input)
	require.NoError(t, err)
	var wire map[string]any
	require.NoError(t, json.Unmarshal(raw, &wire))
	if input.UserIDs != nil {
		wire["userIDs"] = input.UserIDs
	}
	query := fmt.Sprintf("%s($input:UpdateRotationInput!){result:%s(input:$input)%s}", op, field, selection)
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
	var p graphql2.UpdateDeletionPreview
	if !mutation && len(result.Errors) == 0 {
		require.NoError(t, json.Unmarshal(result.Data["result"], &p))
	}
	return &p, result.Errors, w.Body.String()
}

func TestPostgresRotationUpdateSafetyAuthorizationHTTP(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "RotationUpdateSafetyTest")
	app := updateNativeApp(t, ctx, db)
	f := rotationUpdateFixture(t, ctx, db)
	input := rotationUpdateInput(f, 2)
	human := previewAdmit(t, base, db, f.actor)
	ordinary := rotationUpdateInput(f, 4)
	_, problems, body := rotationUpdateHTTP(t, human, app, ordinary, true)
	require.Empty(t, problems, body)
	_, problems, body = rotationUpdateHTTP(t, human, app, input, true)
	require.NotEmpty(t, problems)
	require.Contains(t, body, "DELETION_CONFIRMATION_REQUIRED")
	p, problems, body := rotationUpdateHTTP(t, human, app, input, false)
	require.Empty(t, problems, body)
	require.True(t, p.RequiresConfirmation)
	input.Confirmation = updateNativeConfirmation(p)
	otherActor := previewAdmit(t, base, db, f.user)
	_, err := app.Mutation().UpdateRotation(otherActor, input)
	enforceCode(t, err, ds.DeletionDependencyChanged)
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.user)
	member := previewAdmit(t, base, db, f.user)
	for _, denied := range []context.Context{member, previewAdmit(t, base, db, rotationUpdateFixture(t, ctx, db).actor)} {
		_, problems, body = rotationUpdateHTTP(t, denied, app, input, false)
		require.NotEmpty(t, problems)
		require.NotContains(t, body, f.root.String())
		require.NotContains(t, body, f.user.String())
		_, problems, _ = rotationUpdateHTTP(t, denied, app, input, true)
		require.NotEmpty(t, problems)
	}
	// Reconstruct a fresh version after the relevant user scope changed.
	p, problems, body = rotationUpdateHTTP(t, human, app, input, false)
	require.Empty(t, problems, body)
	input.Confirmation = updateNativeConfirmation(p)
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
	_, err = app.Mutation().UpdateRotation(human, input)
	enforceCode(t, err, ds.DeletionUnavailable)
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, f.actor)
	fresh := previewAdmit(t, base, db, f.actor)
	p, problems, body = rotationUpdateHTTP(t, fresh, app, input, false)
	require.Empty(t, problems, body)
	input.Confirmation = updateNativeConfirmation(p)
	_, problems, body = rotationUpdateHTTP(t, fresh, app, input, true)
	require.Empty(t, problems, body)
}

func TestPostgresRotationUpdateSafetyPlatformAdmin(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "RotationUpdateSafetyTest")
	app := updateNativeApp(t, ctx, db)
	for _, home := range []string{"foreign_normal", "default"} {
		t.Run(home, func(t *testing.T) {
			f := rotationUpdateFixture(t, ctx, db)
			actor := rotationUpdateFixture(t, ctx, db).actor
			enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, actor)
			if home == "default" {
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, actor, organization.DefaultOrganizationID)
			}
			human := previewAdmit(t, base, db, actor)
			input := rotationUpdateInput(f, 2)
			p, err := app.Query().PreviewUpdateRotation(human, input)
			require.NoError(t, err)
			input.Confirmation = updateNativeConfirmation(p)
			ok, err := app.Mutation().UpdateRotation(human, input)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}
