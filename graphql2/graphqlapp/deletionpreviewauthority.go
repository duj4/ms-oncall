package graphqlapp

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/permission"
)

type previewAuthority struct {
	ctx    context.Context
	home   uuid.UUID
	system bool
}

func newPreviewAuthority(ctx context.Context) (previewAuthority, error) {
	a := previewAuthority{ctx: ctx}
	if ctx == nil {
		return a, previewUnavailable()
	}
	if permission.System(ctx) {
		// Exactly the existing compiled internal boundary, never a source-less User.
		if permission.UserID(ctx) != "" || permission.Service(ctx) || permission.Source(ctx) != nil || auth.RequesterFromContext(ctx) != nil || executioncontext.ExecutionContextFromContext(ctx) != nil {
			return a, previewUnavailable()
		}
		a.system = true
		return a, nil
	}
	if _, err := executioncontext.CheckHumanAuthority(ctx); err != nil {
		return a, previewUnavailable()
	}
	home, err := rootStoreOrganizationID(ctx)
	if err != nil || home == nil {
		return a, previewUnavailable()
	}
	a.home = *home
	return a, nil
}

func (a previewAuthority) authorizeTarget(_ context.Context, tx *sql.Tx, t collector.Target) error {
	if tx == nil || (!a.system && t.OrganizationID() != a.home) || !a.canModify(t.Resource(), t.Owner()) {
		return previewUnavailable()
	}
	return nil
}

// Capability checks are the existing read-only admission helpers. CM/NR's
// owner predicate matches CMNRMutationAuthority.AuthorizeUserSnapshot; its
// locking/persistence half is intentionally replaced by Collector's snapshot
// identity, assignment and scope corroboration. No mutation helper is called.
func (a previewAuthority) canModify(obj, owner ds.Resource) bool {
	switch obj.Kind {
	case ds.ResourceService:
		_, err := serviceManagementAuthority(a.ctx, serviceManagementDelete)
		return err == nil
	case ds.ResourceEscalationPolicy, ds.ResourceSchedule, ds.ResourceRotation,
		ds.ResourceEscalationPolicyStep, ds.ResourceEscalationPolicyAction,
		ds.ResourceScheduleRule, ds.ResourceScheduleTarget, ds.ResourceRotationParticipant,
		ds.ResourceTemporarySchedule, ds.ResourceFixedShift, ds.ResourceOnCallNotificationRule:
		_, err := epManagementAuthority(a.ctx, epManagementDelete)
		return err == nil
	case ds.ResourceIntegrationKey:
		_, err := integrationKeyManagementAuthority(a.ctx)
		return err == nil
	case ds.ResourceUser:
		return permission.System(a.ctx) || permission.Admin(a.ctx)
	case ds.ResourceContactMethod, ds.ResourceNotificationRule:
		if _, err := executioncontext.CheckCMNRMutationAuthority(a.ctx); err != nil {
			return false
		}
		return a.system || permission.Admin(a.ctx) || owner.Kind == ds.ResourceUser && owner.ID == permission.UserID(a.ctx)
	case ds.ResourceUserOverride:
		// Existing scoped Override operations permit a Human member in Home.
		return a.system || permission.User(a.ctx)
	default:
		// Runtime/history/identity rows have no independently authorized editor.
		return false
	}
}

// Verification rows do not carry a User reference. Propagate only their
// explicitly collected CM ownership, corroborated by the root authorizer.
// This is a read permission fact, never a new cascade or policy rule.
func previewReferenceOwners(collection ds.Collection, facts map[ds.Resource]collector.Target) map[ds.Resource]ds.Resource {
	owners := make(map[ds.Resource]ds.Resource)
	for root, t := range facts {
		if t.Owner().Kind == ds.ResourceUser {
			owners[root] = t.Owner()
		}
	}
	for _, d := range collection.Dependencies {
		if d.Relationship == ds.RelationshipVerification && d.Target.Kind == ds.ResourceContactMethod && d.Referencing.Kind == ds.ResourceVerificationState {
			if owner, ok := owners[d.Target]; ok {
				owners[d.Referencing] = owner
			}
		}
	}
	return owners
}

func (a previewAuthority) canReadImpact(impact ds.DeletionImpact, owners map[ds.Resource]ds.Resource) bool {
	if a.system || permission.Admin(a.ctx) {
		return true
	}
	for _, r := range []ds.Resource{impact.Target, impact.Referencing, impact.Parent, impact.Owner, impact.Affected} {
		switch r.Kind {
		case ds.ResourceAuthSubject, ds.ResourceUserSession, ds.ResourceBasicAuthLink, ds.ResourceVerificationState:
			owner := impact.Owner
			if known, ok := owners[r]; ok {
				owner = known
			}
			for _, ref := range impact.Before.References {
				if ref.Kind == ds.ResourceUser {
					owner = ref
					break
				}
			}
			if owner.Kind != ds.ResourceUser || owner.ID != permission.UserID(a.ctx) {
				return false
			}
		}
	}
	return true
}
