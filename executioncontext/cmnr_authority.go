package executioncontext

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

// CMNRMutationAuthority is evidence for CM Delete and NR Create/Delete only.
// Its zero value grants nothing. Stores must still resolve and lock the full
// target set and validate CM/NR relationships before writing.
type CMNRMutationAuthority struct {
	valid         bool
	system        bool
	owner         uuid.UUID
	home          uuid.UUID
	platformAdmin bool
}

// CheckCMNRMutationAuthority binds admitted Human evidence to the authenticated
// Requester, actual actor, Session and legacy authentication metadata. It does
// not refresh admission or read Session state during an in-flight request.
// Source-less legacy internal UserContext callers retain owner-only capability,
// including synthetic RoleAdmin; only the canonical constructor supplies Human global
// evidence. System/Sudo remains a separately trusted compiled-code boundary.
func CheckCMNRMutationAuthority(ctx context.Context) (CMNRMutationAuthority, error) {
	var zero CMNRMutationAuthority
	if ctx == nil {
		return zero, permission.NewAccessDenied("")
	}
	if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
		return zero, err
	}
	if permission.System(ctx) {
		return CMNRMutationAuthority{valid: true, system: true}, nil
	}
	owner, err := uuid.Parse(permission.UserID(ctx))
	if err != nil || owner == uuid.Nil {
		return zero, permission.NewAccessDenied("")
	}
	requester := auth.RequesterFromContext(ctx)
	value := ExecutionContextFromContext(ctx)
	source := permission.Source(ctx)
	if requester == nil && value == nil && source == nil {
		return CMNRMutationAuthority{valid: true, owner: owner}, nil
	}
	if requester == nil || value == nil || source == nil ||
		value.PrincipalKind() != PrincipalKindHuman || value.AuthorityMode() != AuthorityModeOrganizationScoped ||
		requester.UserID() != owner || value.PrincipalID() != owner.String() || value.ActualActorID() != owner.String() ||
		source.Type != permission.SourceTypeAuthProvider || source.ID != requester.SessionID().String() ||
		value.AuthenticationSource().Type() != source.Type.String() || value.AuthenticationSource().ID() != source.ID ||
		value.Privileges().PlatformAdmin() != permission.Admin(ctx) {
		return zero, permission.NewAccessDenied("")
	}
	home, ok := value.EffectiveOrganizationID()
	if !ok || !EligibleForOrganizationBusinessScope(value, home) {
		return zero, permission.NewAccessDenied("")
	}
	return CMNRMutationAuthority{valid: true, owner: owner, home: home, platformAdmin: value.Privileges().PlatformAdmin()}, nil
}

// AuthorizeUser validates a locked target owner's current Normal relationship.
// Callers hold the CM/NR locks until the same transaction's write completes.
// The predicates deliberately match organization.FindCurrentUserOrganization:
// no membership, provenance, mapping timestamp or lifecycle policy is invented.
// FOR SHARE (not KEY SHARE) also fences non-key assignment/role updates. All
// callers visit distinct owners in UUID order. System retains its pre-existing
// internal authority without requiring a Human Normal Home assignment.
func (a CMNRMutationAuthority) AuthorizeUser(ctx context.Context, tx *sql.Tx, owner uuid.UUID) error {
	if !a.valid || tx == nil || owner == uuid.Nil || (!a.system && !a.platformAdmin && a.owner != owner) {
		return permission.NewAccessDenied("")
	}
	if a.system {
		// Internal execution does not acquire Human Organization authority,
		// but an existing actual owner must still back the target relationship.
		var id uuid.UUID
		err := tx.QueryRowContext(ctx, `SELECT id FROM public.users WHERE id=$1 FOR KEY SHARE`, owner).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return permission.NewAccessDenied("")
		}
		return err
	}
	var organizationID uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT a.effective_organization_id
		FROM public.users u
		JOIN public.user_organization_assignments a ON a.user_id=u.id
		JOIN public.organizations o ON o.id=a.effective_organization_id
			AND o.classification=a.effective_organization_classification
		JOIN public.normal_organizations n ON n.organization_id=o.id
			AND n.organization_classification=o.classification
			AND n.organization_id=a.effective_normal_organization_id
		WHERE u.id=$1 AND u.role IN ('user','admin')
			AND a.mapping_outcome='EXACTLY_ONE' AND a.matched_count=1
			AND a.effective_organization_classification='NORMAL'
			AND a.effective_organization_id<>$2
			AND a.effective_normal_organization_id=a.effective_organization_id
			AND a.organization_role IN ('ORG_MEMBER','ORG_ADMIN')
			AND o.classification='NORMAL' AND n.organization_classification='NORMAL'
		FOR SHARE OF u,a,o,n`, owner, organization.DefaultOrganizationID).Scan(&organizationID)
	if errors.Is(err, sql.ErrNoRows) {
		return permission.NewAccessDenied("")
	}
	if err != nil {
		return err
	}
	if !a.platformAdmin && a.home != uuid.Nil && a.home != organizationID {
		return permission.NewAccessDenied("")
	}
	return nil
}
