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
		value.PrincipalKind() != PrincipalKindHuman ||
		requester.UserID() != owner || value.PrincipalID() != owner.String() || value.ActualActorID() != owner.String() ||
		source.Type != permission.SourceTypeAuthProvider || source.ID != requester.SessionID().String() ||
		value.AuthenticationSource().Type() != source.Type.String() || value.AuthenticationSource().ID() != source.ID ||
		value.Privileges().PlatformAdmin() != permission.Admin(ctx) {
		return zero, permission.NewAccessDenied("")
	}
	home, ok := value.HomeOrganizationID()
	defaultPA := value.AuthorityMode() == AuthorityModePlatformGlobal && value.Privileges().PlatformAdmin() &&
		home.String() == organization.DefaultOrganizationID && value.Privileges().OrganizationRole() == organization.OrganizationRoleNone
	if !ok || (!EligibleForOrganizationBusinessScope(value, home) && !defaultPA) {
		return zero, permission.NewAccessDenied("")
	}
	return CMNRMutationAuthority{valid: true, owner: owner, home: home, platformAdmin: value.Privileges().PlatformAdmin()}, nil
}

// CMNROrganizationSnapshot is a historical safe projection, not a capability.
type CMNROrganizationSnapshot struct {
	ID         uuid.UUID
	Resolution string
}

// AuthorizeUser preserves the existing authority-only API and predicates.
func (a CMNRMutationAuthority) AuthorizeUser(ctx context.Context, tx *sql.Tx, owner uuid.UUID) error {
	_, err := a.AuthorizeUserSnapshot(ctx, tx, owner)
	return err
}

// AuthorizeUserSnapshot returns the Organization from the original locked
// authorization JOIN. Callers retain CM/NR locks and visit owners in UUID order.
// FOR SHARE fences assignment changes. Trusted System keeps its existing
// authority without acquiring a Human Normal Home requirement.
func (a CMNRMutationAuthority) AuthorizeUserSnapshot(ctx context.Context, tx *sql.Tx, owner uuid.UUID) (CMNROrganizationSnapshot, error) {
	if !a.valid || tx == nil || owner == uuid.Nil || (!a.system && !a.platformAdmin && a.owner != owner) {
		return CMNROrganizationSnapshot{}, permission.NewAccessDenied("")
	}
	if a.system {
		// Internal execution does not acquire Human Organization authority,
		// but an existing actual owner must still back the target relationship.
		var id uuid.UUID
		err := tx.QueryRowContext(ctx, `SELECT id FROM public.users WHERE id=$1 FOR KEY SHARE`, owner).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return CMNROrganizationSnapshot{}, permission.NewAccessDenied("")
		}
		return CMNROrganizationSnapshot{Resolution: "unknown"}, err
	}
	// Lock stable identity keys before resolving the mutable Organization JOIN.
	// After a concurrent Assignment update, READ COMMITTED gives the separate
	// authorization statement below a fresh snapshot. Existence grants nothing.
	var id uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT a.user_id
		FROM public.users u
		JOIN public.user_organization_assignments a ON a.user_id=u.id
		WHERE u.id=$1
		FOR SHARE OF u,a`, owner).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return CMNROrganizationSnapshot{}, permission.NewAccessDenied("")
	}
	if err != nil {
		return CMNROrganizationSnapshot{}, err
	}
	var organizationID uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT a.effective_organization_id
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
		return CMNROrganizationSnapshot{}, permission.NewAccessDenied("")
	}
	if err != nil {
		return CMNROrganizationSnapshot{}, err
	}
	if !a.platformAdmin && a.home != uuid.Nil && a.home != organizationID {
		return CMNROrganizationSnapshot{}, permission.NewAccessDenied("")
	}
	return CMNROrganizationSnapshot{ID: organizationID, Resolution: "known_normal"}, nil
}

// SnapshotCMNROrganization resolves additional effect owners without performing
// actor/owner authorization or inventing a new permission condition. Missing or
// inconsistent assignments are explicitly unknown; SQL failure remains fatal.
// Callers already hold the affected business row locks, visit owners in UUID
// order, and retain these locks until the original transaction ends.
func SnapshotCMNROrganization(ctx context.Context, tx *sql.Tx, owner uuid.UUID) (CMNROrganizationSnapshot, error) {
	unknown := CMNROrganizationSnapshot{Resolution: "unknown"}
	var id uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT a.user_id FROM public.users u
	 JOIN public.user_organization_assignments a ON a.user_id=u.id
	 WHERE u.id=$1 FOR SHARE OF u,a`, owner).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return unknown, nil
	}
	if err != nil {
		return unknown, err
	}
	var resolution string
	err = tx.QueryRowContext(ctx, `SELECT o.id, CASE WHEN o.classification='NORMAL' THEN 'known_normal' ELSE 'known_default' END
	 FROM public.users u JOIN public.user_organization_assignments a ON a.user_id=u.id
	 JOIN public.organizations o ON o.id=a.effective_organization_id AND o.classification=a.effective_organization_classification
	 WHERE u.id=$1 AND u.role IN ('user','admin') AND (
	 (o.classification='NORMAL' AND o.id<>$2 AND a.mapping_outcome='EXACTLY_ONE' AND a.matched_count=1
	 AND a.effective_normal_organization_id=o.id AND a.organization_role IN ('ORG_MEMBER','ORG_ADMIN'))
	 OR (o.classification='DEFAULT' AND o.id=$2 AND a.effective_normal_organization_id IS NULL AND a.organization_role='NONE'))
	 FOR SHARE OF u,a,o`, owner, organization.DefaultOrganizationID).Scan(&id, &resolution)
	if errors.Is(err, sql.ErrNoRows) {
		return unknown, nil
	}
	if err != nil {
		return unknown, err
	}
	if resolution == "known_normal" {
		var normal uuid.UUID
		err = tx.QueryRowContext(ctx, `SELECT organization_id FROM public.normal_organizations WHERE organization_id=$1 AND organization_classification='NORMAL' FOR SHARE`, id).Scan(&normal)
		if errors.Is(err, sql.ErrNoRows) {
			return unknown, nil
		}
		if err != nil {
			return unknown, err
		}
	}
	return CMNROrganizationSnapshot{ID: id, Resolution: resolution}, nil
}
