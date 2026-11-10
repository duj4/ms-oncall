package graphqlapp

import (
	"context"
	"database/sql"
	"slices"

	"github.com/google/uuid"
	"github.com/target/goalert/integrationkey"
	keyaudit "github.com/target/goalert/integrationkey/deleteaudit"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/validation/validate"
)

// deleteIntegrationKeysWithAudit uses the shared DeleteAll transaction for
// authorization, safe identity capture and every scoped DELETE.
func (a *Mutation) deleteIntegrationKeysWithAudit(ctx context.Context, tx *sql.Tx, ids []string, audit *deleteAllAttempt) (resultErr error) {
	if audit != nil {
		defer func() { resultErr = audit.keyCaptureError(resultErr) }()
	}
	authority, err := integrationKeyManagementAuthority(ctx)
	if err != nil {
		return err
	}
	if authority.system && audit == nil {
		return a.IntKeyStore.DeleteMany(ctx, tx, ids, nil)
	}
	keyIDs, err := validate.ParseManyUUID("IntegrationKeyID", ids, 50) // Raw count, before deduplication.
	if err != nil {
		return err
	}
	ids = make([]string, len(keyIDs))
	for i, id := range keyIDs {
		ids[i] = id.String()
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	groups := make(map[uuid.UUID][]string)
	var organizations []string
	var candidates []serviceKeyReceipt
	for _, id := range ids {
		var locked uuid.UUID
		if authority.system {
			err = tx.QueryRowContext(ctx, `SELECT id FROM integration_keys WHERE id=$1 FOR UPDATE`, id).Scan(&locked)
			if err == sql.ErrNoRows {
				continue
			}
		} else {
			err = tx.QueryRowContext(ctx, `SELECT k.id FROM integration_keys k JOIN services s ON s.id=k.service_id `+integrationKeyNormalServiceJoin+` WHERE k.id=$1 FOR UPDATE OF k FOR SHARE OF s,o,n`, id).Scan(&locked)
			if err == sql.ErrNoRows {
				return integrationKeyAccessDenied()
			}
		}
		if err != nil {
			return err
		}
		// Authorize before a safe target can enter even a failure observation.
		var scope *uuid.UUID
		if !authority.system {
			scope, _, err = authority.keyTarget(ctx, tx, id)
			if err != nil {
				return err
			}
			if scope == nil {
				return integrationKeyAccessDenied()
			}
		}
		if audit != nil {
			r, err := audit.captureKey(ctx, tx, id, scope)
			if err != nil {
				return err
			}
			candidates = append(candidates, r)
		}
		if authority.system {
			continue
		}
		if _, exists := groups[*scope]; !exists {
			organizations = append(organizations, scope.String())
		}
		groups[*scope] = append(groups[*scope], id)
	}
	if audit == nil {
		slices.Sort(organizations)
		for _, org := range organizations {
			scope := uuid.MustParse(org)
			if err := a.IntKeyStore.DeleteMany(ctx, tx, groups[scope], &scope); err != nil {
				return err
			}
		}
		return nil
	}
	var result []integrationkey.DeleteReceipt
	if authority.system {
		result, err = a.IntKeyStore.DeleteManyForAuditTx(ctx, tx, ids, nil)
	} else {
		slices.Sort(organizations)
		for _, org := range organizations {
			scope := uuid.MustParse(org)
			var receipts []integrationkey.DeleteReceipt
			receipts, err = a.IntKeyStore.DeleteManyForAuditTx(ctx, tx, groups[scope], &scope)
			if err != nil {
				break
			}
			result = append(result, receipts...)
		}
	}
	if err != nil {
		return err
	}
	return audit.collectKeyReceipts(candidates, result)
}

// captureKey uses fresh statements after Key and parent lock waits. Credential
// input is only a SQL predicate; it never becomes an audit identity or payload.
func (a *deleteAllAttempt) captureKey(ctx context.Context, tx *sql.Tx, credential string, scope *uuid.UUID) (serviceKeyReceipt, error) {
	var r serviceKeyReceipt
	if err := tx.QueryRowContext(ctx, `SELECT service_id FROM integration_keys WHERE id=$1`, credential).Scan(&r.root); err != nil {
		return r, err
	}
	var locked uuid.UUID
	if err := tx.QueryRowContext(ctx, `SELECT id FROM services WHERE id=$1 FOR SHARE`, r.root).Scan(&locked); err != nil {
		return r, err
	}
	// Retain the actual organization classification and Normal subtype too.
	var class string
	if err := tx.QueryRowContext(ctx, `SELECT o.id,o.classification FROM services s JOIN organizations o ON o.id=s.organization_id WHERE s.id=$1 FOR SHARE OF o`, r.root).Scan(&r.org, &class); err != nil {
		return r, err
	}
	resolution := "known_normal"
	if class == "NORMAL" {
		if err := tx.QueryRowContext(ctx, `SELECT organization_id FROM normal_organizations WHERE organization_id=$1 FOR SHARE`, r.org).Scan(&locked); err != nil {
			return r, err
		}
	} else if class == "DEFAULT" && r.org.String() == organization.DefaultOrganizationID {
		resolution = "known_default"
	} else {
		return r, keyaudit.ErrInvalid
	}
	var parent, org uuid.UUID
	if err := tx.QueryRowContext(ctx, `SELECT k.audit_resource_id,k.service_id,s.organization_id FROM integration_keys k JOIN services s ON s.id=k.service_id WHERE k.id=$1`, credential).Scan(&r.resource, &parent, &org); err != nil {
		return r, err
	}
	credentialID, _ := uuid.Parse(credential)
	if r.resource == credentialID || r.resource == uuid.Nil || parent != r.root || org != r.org || scope != nil && org != *scope {
		return r, keyaudit.ErrInvalid
	}
	e := a.keyEvent
	e.EventID, e.ResourceID, e.ParentServiceID, e.TargetOrganizationID, e.TargetOrgResolution = uuid.New(), r.resource, r.root, r.org, resolution
	a.keyTargets = append(a.keyTargets, e)
	return r, nil
}
