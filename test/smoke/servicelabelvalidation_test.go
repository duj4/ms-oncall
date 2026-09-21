package smoke

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/label"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/search"
	"github.com/target/goalert/service"
)

func TestServiceLabelValidationPrecedence(t *testing.T) {
	h := serviceLabelHarness(t)
	app := serviceLabelApp(h)
	const (
		typeError     = "invalid value for 'TargetType': must be one of: TargetTypeService"
		idError       = "invalid value for 'TargetID': must be valid UUID: format must be xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
		keyError      = "invalid value for 'Key': prefix and suffix must be separated by `/`"
		valueError    = "invalid value for 'Value': must be at least 3 characters"
		disabledError = "invalid value for 'Key': Creating new labels is currently disabled."
	)
	// These exact messages/order were established on the frozen implementation
	// base. Malformed input does not depend on the target Service's ownership.
	for _, principal := range []string{"user-a", "missing"} {
		for _, disabled := range []bool{false, true} {
			ctx := serviceLabelHuman(t, h, principal)
			cfg := h.Config()
			cfg.General.DisableLabelCreation = disabled
			ctx = cfg.Context(ctx)
			for _, tc := range []struct {
				name, want string
				mutate     func(*graphql2.SetLabelInput)
				newKey     bool
			}{
				{"type", typeError, func(i *graphql2.SetLabelInput) { i.Target.Type = assignment.TargetTypeUser }, false},
				{"id", idError, func(i *graphql2.SetLabelInput) { i.Target.ID = "bad" }, false},
				{"key", keyError, func(i *graphql2.SetLabelInput) { i.Key = "bad" }, true},
				{"value", valueError, func(i *graphql2.SetLabelInput) { i.Value = "x" }, false},
				{"multiple", typeError + "\n" + idError + "\n" + keyError + "\n" + valueError, func(i *graphql2.SetLabelInput) {
					i.Target.Type, i.Target.ID, i.Key, i.Value = assignment.TargetTypeUser, "bad", "bad", "x"
				}, true},
			} {
				t.Run(principal+"/disabled="+map[bool]string{false: "false", true: "true"}[disabled]+"/"+tc.name, func(t *testing.T) {
					input := serviceLabelInput("b", "aaa/own", "value")
					tc.mutate(&input)
					ok, err := app.Mutation().SetLabel(ctx, input)
					require.False(t, ok)
					if disabled && principal == "missing" {
						// Without authority, there is no eligible key set to consult.
						require.True(t, permission.IsPermissionError(err))
						return
					}
					want := tc.want
					if disabled && tc.newKey {
						want = disabledError
					}
					require.EqualError(t, err, want)
				})
			}
		}
	}
	for _, principal := range []string{"user-a", "missing"} {
		ctx := serviceLabelHuman(t, h, principal)
		badSearch, badCursor := strings.Repeat("x", 256), "!"
		large, negative := 1000, -2
		for _, tc := range []struct {
			name  string
			input graphql2.LabelKeySearchOptions
			want  string
		}{
			{"search", graphql2.LabelKeySearchOptions{Search: &badSearch}, "invalid value for 'Search': cannot exceed 255 characters"},
			{"cursor", graphql2.LabelKeySearchOptions{After: &badCursor, Search: &badSearch}, "invalid value for 'Cursor': illegal base64 data at input byte 0"},
			{"limit", graphql2.LabelKeySearchOptions{First: &large}, "invalid value for 'Limit': must not be over 150"},
			{"negative-limit", graphql2.LabelKeySearchOptions{First: &negative}, "invalid value for 'Limit': must not be negative"},
			{"omit", graphql2.LabelKeySearchOptions{Omit: []string{"bad"}}, "invalid value for 'Omit[0]': prefix and suffix must be separated by `/`"},
			{"omit-count", graphql2.LabelKeySearchOptions{Omit: make([]string, 51)}, "invalid value for 'Omit': must not be over 50"},
		} {
			t.Run(principal+"/search/"+tc.name, func(t *testing.T) {
				_, err := app.Query().LabelKeys(ctx, &tc.input)
				require.EqualError(t, err, tc.want)
				_, err = app.Query().LabelValues(ctx, &graphql2.LabelValueSearchOptions{Key: "org/shared", First: tc.input.First, Search: tc.input.Search, After: tc.input.After, Omit: tc.input.Omit})
				require.EqualError(t, err, tc.want)
			})
		}
		cursor, err := search.Cursor(label.KeySearchOptions{After: "bad"})
		require.NoError(t, err)
		_, err = app.Query().LabelKeys(ctx, &graphql2.LabelKeySearchOptions{After: &cursor})
		require.EqualError(t, err, "invalid value for 'After': prefix and suffix must be separated by `/`")
		_, err = app.Query().LabelValues(ctx, &graphql2.LabelValueSearchOptions{Key: badSearch})
		require.EqualError(t, err, "invalid value for 'Key': cannot exceed 255 characters")
		_, err = app.Service().Labels(ctx, &service.Service{ID: "bad"})
		require.EqualError(t, err, "invalid value for 'ServiceID': must be valid UUID: format must be xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
	}
}

func TestServiceLabelAuthorityAndCreationPolicy(t *testing.T) {
	h := serviceLabelHarness(t)
	app := serviceLabelApp(h)
	valid := serviceLabelHuman(t, h, "user-a")
	human := auth.WithRequester(permission.UserSourceContext(h.Config().Context(t.Context()), serviceLabelID("user-a"), permission.RoleUser, permission.Source(valid)), *auth.RequesterFromContext(valid))
	contexts := map[string]context.Context{
		"missing assignment":   serviceLabelHuman(t, h, "missing"),
		"default assignment":   serviceLabelHuman(t, h, "default"),
		"missing authority":    human,
		"zero authority":       executioncontext.WithExecutionContext(human, executioncontext.ExecutionContext{}),
		"missing requester":    permission.UserSourceContext(h.Config().Context(t.Context()), serviceLabelID("user-a"), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}),
		"inconsistent source":  permission.UserSourceContext(valid, serviceLabelID("user-a"), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}),
		"inconsistent user":    permission.UserSourceContext(valid, serviceLabelID("user-b"), permission.RoleUser, permission.Source(valid)),
		"inconsistent session": permission.UserSourceContext(valid, serviceLabelID("user-a"), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}),
	}
	for name, ctx := range contexts {
		t.Run(name, func(t *testing.T) {
			before := serviceLabelSnapshot(t, h, "a")
			_, err := app.Query().LabelKeys(ctx, nil)
			require.True(t, permission.IsPermissionError(err))
			_, err = app.Query().LabelValues(ctx, &graphql2.LabelValueSearchOptions{Key: "org/shared"})
			require.True(t, permission.IsPermissionError(err))
			_, err = app.Query().Labels(ctx, nil)
			require.True(t, permission.IsPermissionError(err))
			_, err = app.Service().Labels(ctx, &service.Service{ID: serviceLabelID("a")})
			require.True(t, permission.IsPermissionError(err))
			for _, value := range []string{"updated", ""} {
				ok, err := app.Mutation().SetLabel(ctx, serviceLabelInput("a", "aaa/own", value))
				require.False(t, ok)
				require.True(t, permission.IsPermissionError(err))
			}
			require.Equal(t, before, serviceLabelSnapshot(t, h, "a"))
		})
	}
	for _, principal := range []string{"missing", "default"} {
		response := serviceLabelHTTP(t, h, principal, `query { labelKeys { nodes } }`, nil)
		require.Len(t, response.Errors, 1)
		require.Contains(t, response.Errors[0].Message, "normal Organization scoped authority is required")
		response = serviceLabelHTTP(t, h, principal, `mutation($input:SetLabelInput!){setLabel(input:$input)}`, serviceLabelVariables("a", "aaa/own", "value"))
		require.Len(t, response.Errors, 1)
		require.Contains(t, response.Errors[0].Message, "normal Organization scoped authority is required")
	}
	for _, principal := range []string{"user-a", "admin-a"} {
		cfg := h.Config()
		cfg.General.DisableLabelCreation = true
		ctx := cfg.Context(serviceLabelHuman(t, h, principal))
		for _, tc := range []struct {
			target, key, value string
			allowed            bool
		}{
			{"a", "bbb/foreign", "value", false},
			{"a", "new/label", "value", false},
			{"a2", "aaa/own", "created", true},
			{"a2", "aaa/own", "updated", true},
			{"a2", "aaa/own", "", true},
		} {
			before := serviceLabelSnapshot(t, h, tc.target)
			ok, err := app.Mutation().SetLabel(ctx, serviceLabelInput(tc.target, tc.key, tc.value))
			if tc.allowed {
				require.NoError(t, err)
				require.True(t, ok)
			} else {
				require.False(t, ok)
				require.EqualError(t, err, "invalid value for 'Key': Creating new labels is currently disabled.")
				require.Equal(t, before, serviceLabelSnapshot(t, h, tc.target))
			}
		}
		before := serviceLabelSnapshot(t, h, "b")
		_, err := app.Mutation().SetLabel(ctx, serviceLabelInput("b", "org/shared", "updated"))
		require.ErrorIs(t, err, sql.ErrNoRows)
		require.Equal(t, before, serviceLabelSnapshot(t, h, "b"))
	}
	// System/nil retains the old global allowed-key set.
	cfg := h.Config()
	cfg.General.DisableLabelCreation = true
	ok, err := app.Mutation().SetLabel(permission.SystemContext(cfg.Context(t.Context()), "Smoketest"), serviceLabelInput("a", "bbb/foreign", "value"))
	require.NoError(t, err)
	require.True(t, ok)
}
