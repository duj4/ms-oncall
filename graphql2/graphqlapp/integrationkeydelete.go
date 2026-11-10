package graphqlapp

import (
	"context"
	"database/sql"
	"slices"

	"github.com/google/uuid"
	"github.com/target/goalert/service/deleteaudit"
	"github.com/target/goalert/validation/validate"
)

// deleteIntegrationKeys uses the DeleteAll transaction for both authorization
// and every scoped delete. A Human never reaches the Store's nil-scope path.
func (a *Mutation) deleteIntegrationKeys(ctx context.Context, tx *sql.Tx, ids []string) error {
	return a.deleteIntegrationKeysWithAudit(ctx, tx, ids, nil)
}

func (a *Mutation) deleteIntegrationKeysWithAudit(ctx context.Context, tx *sql.Tx, ids []string, audit *serviceDeleteAttempt) (resultErr error) {
	if audit != nil {
		defer func() { resultErr = audit.captureError(resultErr) }()
	}
	authority, err := integrationKeyManagementAuthority(ctx)
	if err != nil {
		return err
	}
	if authority.system && audit == nil {
		return a.IntKeyStore.DeleteMany(ctx, tx, ids, nil)
	}
	keyIDs, err := validate.ParseManyUUID("IntegrationKeyID", ids, 50)
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
	for _, id := range ids {
		// Hold the actual type/parent and owning Normal Organization stable
		// until commit. Share locks permit other Key operations while preventing
		// concurrent parent/Organization changes from invalidating authority.
		var locked uuid.UUID
		if authority.system {
			err = tx.QueryRowContext(ctx, `SELECT id FROM integration_keys WHERE id=$1 FOR UPDATE`, id).Scan(&locked)
			if err == sql.ErrNoRows {
				continue
			}
			if err != nil {
				return err
			}
		} else {
			err = tx.QueryRowContext(ctx, `
			SELECT k.id FROM integration_keys k
			JOIN services s ON s.id = k.service_id
		`+integrationKeyNormalServiceJoin+`
			WHERE k.id = $1
			FOR UPDATE OF k FOR SHARE OF s, o, n
		`, id).Scan(&locked)
			if err == sql.ErrNoRows {
				return integrationKeyAccessDenied()
			}
			if err != nil {
				return err
			}
		}
		if audit != nil {
			// Independent statements follow the key lock and parent lock waits.
			// Only safe identities leave this transaction; the request UUID stays
			// in the existing in-memory credential matching path.
			var parent, resource, org uuid.UUID
			if err := tx.QueryRowContext(ctx, `SELECT service_id FROM integration_keys WHERE id=$1`, id).Scan(&parent); err != nil {
				return err
			}
			if err := tx.QueryRowContext(ctx, `SELECT id FROM services WHERE id=$1 FOR SHARE`, parent).Scan(&locked); err != nil {
				return err
			}
			if err := tx.QueryRowContext(ctx, `SELECT k.audit_resource_id,s.id,s.organization_id FROM integration_keys k JOIN services s ON s.id=k.service_id WHERE k.id=$1`, id).Scan(&resource, &locked, &org); err != nil {
				return err
			}
			if locked != parent || resource == uuid.Nil {
				return deleteaudit.ErrInvalid
			}
			if audit.plan.serviceIDs[parent] {
				audit.keyReceipts = append(audit.keyReceipts, serviceKeyReceipt{resource, parent, org})
			}
		}
		if authority.system {
			continue
		}
		scope, _, err := authority.keyTarget(ctx, tx, id)
		if err != nil {
			return err
		}
		if scope == nil { // Fail closed even if a future authority path changes.
			return integrationKeyAccessDenied()
		}
		if _, exists := groups[*scope]; !exists {
			organizations = append(organizations, scope.String())
		}
		groups[*scope] = append(groups[*scope], id)
	}
	if authority.system {
		return a.deleteIntegrationKeyReceipts(ctx, tx, ids, nil, audit)
	}
	slices.Sort(organizations)
	for _, org := range organizations {
		scope := uuid.MustParse(org) // Only server-owned UUIDs enter this slice.
		if err := a.deleteIntegrationKeyReceipts(ctx, tx, groups[scope], &scope, audit); err != nil {
			return err
		}
	}
	return nil
}

func (a *Mutation) deleteIntegrationKeyReceipts(ctx context.Context, tx *sql.Tx, ids []string, scope *uuid.UUID, audit *serviceDeleteAttempt) error {
	if audit == nil {
		return a.IntKeyStore.DeleteMany(ctx, tx, ids, scope)
	}
	result, err := a.IntKeyStore.DeleteManyForAuditTx(ctx, tx, ids, scope)
	if err != nil {
		return err
	}
	// Reconcile captured candidates with actual receipts, including suppressed
	// System deletes. Captured-but-not-deleted keys remain available for the
	// later Service capture (and its late-explicit classification).
	got := map[uuid.UUID]uuid.UUID{}
	for _, r := range result {
		if r.ResourceID == uuid.Nil || r.ServiceID == uuid.Nil {
			return deleteaudit.ErrInvalid
		}
		if _, exists := got[r.ResourceID]; exists {
			return deleteaudit.ErrInvalid
		}
		got[r.ResourceID] = r.ServiceID
	}
	kept := audit.keyReceipts[:0]
	for _, r := range audit.keyReceipts {
		parent, exists := got[r.resource]
		if !exists {
			// Other Organization groups have yet to execute (or already did).
			if scope == nil || r.org == *scope {
				continue
			}
		} else if parent != r.root {
			return deleteaudit.ErrInvalid
		}
		kept = append(kept, r)
		if exists {
			delete(got, r.resource)
		}
	}
	for _, root := range got {
		if audit.plan.serviceIDs[root] {
			return deleteaudit.ErrInvalid
		}
	}
	audit.keyReceipts = kept
	if len(kept) > deleteaudit.MaxEffects {
		return deleteaudit.ErrCapacity
	}
	return nil
}
