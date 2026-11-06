package graphqlapp

import (
	"context"
	"database/sql"
	"slices"

	"github.com/google/uuid"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/validation/validate"
)

// serviceDeleteTargetOrganization resolves only the Service group, in the same
// transaction as its scoped DELETE. Other DeleteAll groups retain their own
// authority. Cross-Organization Service sets remain unsupported.
func serviceDeleteTargetOrganization(ctx context.Context, tx *sql.Tx, ids []string) (*uuid.UUID, error) {
	home, err := serviceManagementAuthority(ctx, serviceManagementDelete)
	if err != nil || home == nil {
		return home, err // Preserve only the existing explicit trusted System path.
	}
	if !executioncontext.ExecutionContextFromContext(ctx).Privileges().PlatformAdmin() {
		return home, nil
	}
	parsed, err := validate.ParseManyUUID("ServiceID", ids, 50)
	if err != nil {
		return nil, err
	}
	ids = make([]string, len(parsed))
	for i, id := range parsed {
		ids[i] = id.String()
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)

	var target *uuid.UUID
	for _, id := range ids {
		// Lock the root before following its current relationships in separate
		// statements. A joined locking read can follow a stale parent after a
		// concurrent reparenting commits while the root lock is awaited.
		// UPDATE also fences new FK dependents during DELETE's cascades; SHARE
		// alone (sufficient for some updates) would not block FK KEY SHARE.
		var org uuid.UUID
		var policy string
		err := tx.QueryRowContext(ctx, `SELECT organization_id, escalation_policy_id
			FROM services WHERE id=$1 FOR UPDATE`, id).Scan(&org, &policy)
		if err != nil {
			return nil, err
		}
		var locked uuid.UUID
		err = tx.QueryRowContext(ctx, `SELECT o.id FROM organizations o
			JOIN normal_organizations n ON n.organization_id=o.id
				AND n.organization_classification=o.classification
			WHERE o.id=$1 AND o.classification='NORMAL' AND o.id<>$2 AND o.id<>$3
			FOR SHARE OF o, n`, org, organization.DefaultOrganizationID, uuid.Nil).Scan(&locked)
		if err != nil {
			return nil, err
		}
		err = tx.QueryRowContext(ctx, `SELECT id FROM escalation_policies
			WHERE id=$1 AND organization_id=$2 FOR SHARE`, policy, org).Scan(&locked)
		if err != nil {
			return nil, err
		}
		if target != nil && *target != org {
			return nil, sql.ErrNoRows
		}
		target = &org
	}
	if target == nil {
		return home, nil
	}
	return target, nil
}
