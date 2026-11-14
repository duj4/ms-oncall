package graphqlapp

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

func TestSessionAuditTrustedAttribution(t *testing.T) {
	ctx, _, _ := ikAuthorityContext(t, organization.OrganizationRoleMember, false)
	e := sessionAuditEvent(ctx, "selected_sessions")
	require.NoError(t, e.Validate())
	require.Equal(t, "human", e.ActorKind)
	require.Equal(t, e.ActorID, e.InitiatorUserID)
	p := newDeleteAllAudit(ctx, nil, []assignment.RawTarget{{Type: assignment.TargetTypeUserSession, ID: uuid.NewString()}})
	require.NotNil(t, p)
	one, two := p.nextAttempt(), p.nextAttempt()
	require.Equal(t, one.sessionEvent.ExecutionID, two.sessionEvent.ExecutionID)
	require.NotEqual(t, one.sessionEvent.AttemptID, two.sessionEvent.AttemptID)
	for _, ctx := range []context.Context{context.Background(), permission.UserContext(context.Background(), uuid.NewString(), permission.RoleAdmin), permission.SystemContext(ctx, "Forged"), permission.SourceContext(sd3InternalSystemContext(), &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()})} {
		require.Equal(t, "unknown", sessionAuditEvent(ctx, "selected_sessions").ActorKind)
	}
	system := sessionAuditEvent(sd3InternalSystemContext(), "selected_sessions")
	require.Equal(t, "internal_system", system.ActorKind)
	require.NoError(t, system.Validate())
	require.Equal(t, "unknown", sessionAuditEvent(sd3InternalSystemContext(), "other_sessions_of_current_user").ActorKind)
	for _, err := range []error{errors.New("SYNTHETIC_RAW_DRIVER"), permission.Unauthorized(), permission.NewAccessDenied("SYNTHETIC_AUTH_REASON")} {
		require.NotContains(t, sessionAuditSafeError(err).Error(), "SYNTHETIC")
	}
}
func TestSessionAuditMissingAuthorityAndOwnership(t *testing.T) {
	m := new(App).Mutation()
	ok, err := m.EndAllAuthSessionsByCurrentUser(context.Background())
	require.False(t, ok)
	require.Error(t, err)
	ctx, _, _ := ikAuthorityContext(t, organization.OrganizationRoleMember, false)
	// No DB access can occur through an inherited controller-owned transaction.
	// The direct absence test also proves no legacy autocommit fallback.
	ok, err = m.EndAllAuthSessionsByCurrentUser(ctx)
	require.False(t, ok)
	require.Error(t, err)
}

func TestSessionAuditCannotCommitWithoutReceipt(t *testing.T) {
	p := newDeleteAllAudit(sd3InternalSystemContext(), nil, []assignment.RawTarget{{Type: assignment.TargetTypeUserSession}})
	a := p.nextAttempt()
	require.Error(t, a.commit(t.Context()))
	require.True(t, a.auditFailed)
	require.False(t, a.commitAttempted)
}
