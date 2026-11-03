package graphqlapp

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/99designs/gqlgen/graphql"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util/log"
	"github.com/vektah/gqlparser/v2/ast"
)

func TestServiceUpdateDiagnosticProjection(t *testing.T) {
	ctx, _, f := ikAuthorityContext(t, organization.OrganizationRoleAdmin, true)
	ctx = log.WithLogger(ctx, log.NewLogger())
	ctx = log.SetRequestID(log.WithField(ctx, "Cookie", "SYNTHETIC_COOKIE"))
	for _, tc := range []struct {
		object, name, alias string
		selected            bool
	}{
		{"Mutation", "updateService", "updateService", true},
		{"Mutation", "updateService", "untrustedAlias", true},
		{"Mutation", "createService", "updateService", false},
		{"Query", "service", "updateService", false},
	} {
		field := &graphql.FieldContext{Object: tc.object, Field: graphql.CollectedField{Field: &ast.Field{Name: tc.name, Alias: tc.alias}}}
		original := graphql.WithFieldContext(ctx, field)
		projected := serviceUpdateDiagnosticContext(original)
		if !tc.selected {
			require.Equal(t, original, projected)
			continue
		}
		var out bytes.Buffer
		logger := log.FromContext(ctx)
		logger.SetOutput(&out)
		log.Logf(projected, "Mutation.")
		require.Contains(t, out.String(), "MutationName=updateService")
		require.Contains(t, out.String(), log.RequestID(ctx))
		for _, secret := range []string{"SYNTHETIC_COOKIE", "AuthSource", f.session.String(), tc.alias + "="} {
			require.NotContains(t, out.String(), secret)
		}
		require.Equal(t, f.session.String(), permission.Source(original).ID)
		require.Equal(t, f.user.String(), permission.UserID(original))
		require.True(t, permission.Admin(original))
	}
}

func TestServiceUpdateAuditIdentityProjection(t *testing.T) {
	for _, role := range []organization.OrganizationRole{organization.OrganizationRoleAdmin, organization.OrganizationRoleMember} {
		for _, pa := range []bool{true, false} {
			ctx, _, f := ikAuthorityContext(t, role, pa)
			ctx = log.SetRequestID(ctx)
			input := graphql2.UpdateServiceInput{ID: uuid.NewString()}
			e := serviceUpdateAuditEvent(ctx, input)
			require.Equal(t, "human", e.ActorKind)
			require.Equal(t, f.user, e.ActorID)
			require.Equal(t, f.home, e.HomeOrganizationID)
			require.Equal(t, string(role), e.OrganizationRole)
			require.Equal(t, uuid.Nil, e.ServiceID, "untrusted input is not an actual target")
			require.Equal(t, uuid.Nil, e.TargetOrganizationID)
			require.Equal(t, log.RequestID(ctx), e.RequestID.String())
			e2 := serviceUpdateAuditEvent(ctx, input)
			require.Equal(t, e.RequestID, e2.RequestID)
			require.NotEqual(t, e.AttemptID, e2.AttemptID)
			require.NotEqual(t, e.EventID, e2.EventID)
			other, err := auth.NewRequester(uuid.NewString(), uuid.NewString())
			require.NoError(t, err)
			for _, bad := range []context.Context{nil, context.Background(), auth.WithRequester(ctx, other), permission.UserContext(ctx, f.user.String(), permission.RoleUser), permission.SystemContext(ctx, "Test")} {
				// The unchanged User role is a valid control for ordinary users.
				if !pa && bad != nil && permission.User(bad) && auth.RequesterFromContext(bad) != nil && auth.RequesterFromContext(bad).UserID() == f.user && !permission.System(bad) {
					continue
				}
				x := serviceUpdateAuditEvent(bad, input)
				require.Equal(t, "unknown", x.ActorKind)
				require.Equal(t, uuid.Nil, x.ActorID)
				require.Equal(t, uuid.Nil, x.HomeOrganizationID)
			}
			require.Equal(t, 1, f.queries, "projection must not reread or replace admission authority")
		}
	}
}

func TestServiceUpdateAuditCommitEvidence(t *testing.T) {
	require.NotContains(t, serviceUpdateSafeError(&pgconn.PgError{Code: "23514", ConstraintName: "user_override_no_conflict_allowed", Hint: "SYNTHETIC_SQL_SECRET"}).Error(), "SYNTHETIC_SQL_SECRET")
	require.Equal(t, sql.ErrNoRows, serviceUpdateSafeError(fmt.Errorf("SYNTHETIC_SQL_SECRET: %w", sql.ErrNoRows)))
	for _, tc := range []struct {
		err     error
		outcome string
	}{
		{driver.ErrBadConn, "commit_unknown"}, {context.Canceled, "commit_unknown"}, {context.DeadlineExceeded, "commit_unknown"}, {sql.ErrTxDone, "commit_unknown"}, {errors.New("synthetic SQL secret"), "commit_unknown"},
		{&pgconn.PgError{Code: "23514", Message: "synthetic SQL secret"}, "tx_failed"}, {&pgconn.PgError{Code: "40001"}, "tx_failed"}, {&pgconn.PgError{Code: "P0001"}, "tx_failed"}, {&pgconn.PgError{Code: "08006"}, "commit_unknown"},
	} {
		outcome, _ := serviceUpdateCommitOutcome(tc.err)
		require.Equal(t, tc.outcome, outcome)
		require.NotContains(t, serviceUpdateSafeError(tc.err).Error(), "synthetic SQL secret")
	}
	outcome, _ := serviceUpdateCommitOutcome(&pgconn.PgError{Code: "40003"})
	require.Equal(t, "commit_unknown", outcome, "statement_completion_unknown must not be folded into rollback class 40")
}

func TestServiceUpdateAuditFaultLogDoesNotInheritContext(t *testing.T) {
	ctx, _, _ := ikAuthorityContext(t, organization.OrganizationRoleMember, false)
	logger := log.NewLogger()
	var out bytes.Buffer
	logger.SetOutput(&out)
	ctx = log.WithField(log.WithLogger(ctx, logger), "InjectedField", "SYNTHETIC_LOG_SECRET")
	ctx = log.SetRequestID(ctx)
	_, err := new(App).Mutation().UpdateService(ctx, graphql2.UpdateServiceInput{ID: uuid.NewString()})
	require.Error(t, err)
	require.True(t, permission.IsPermissionError(err))
	require.Contains(t, err.Error(), "audit persistence unavailable")
	require.Contains(t, out.String(), "AuditAttemptID")
	require.Contains(t, out.String(), log.RequestID(ctx))
	require.NotContains(t, out.String(), "SYNTHETIC_LOG_SECRET")
	require.NotContains(t, out.String(), "AuthSource")
}

func TestServiceUpdateAuditNoInputOrCredentialProjection(t *testing.T) {
	ctx, _, f := ikAuthorityContext(t, organization.OrganizationRoleAdmin, true)
	sentinel := "SYNTHETIC_TOKEN_DESTINATION_DESCRIPTION"
	ctx = log.WithField(ctx, "Authorization", sentinel)
	e := serviceUpdateAuditEvent(ctx, graphql2.UpdateServiceInput{ID: sentinel, Name: &sentinel, Description: &sentinel, EscalationPolicyID: &sentinel})
	b, err := json.Marshal(e)
	require.NoError(t, err)
	require.NotContains(t, string(b), sentinel)
	require.NotContains(t, string(b), f.session.String())
	require.EqualValues(t, 11, e.RequestedFields)
	credentialID := uuid.NewString()
	untrusted := permission.ServiceSourceContext(context.Background(), uuid.NewString(), &permission.SourceInfo{Type: permission.SourceTypeIntegrationKey, ID: credentialID})
	b, err = json.Marshal(serviceUpdateAuditEvent(untrusted, graphql2.UpdateServiceInput{ID: credentialID}))
	require.NoError(t, err)
	require.NotContains(t, string(b), credentialID)
}
