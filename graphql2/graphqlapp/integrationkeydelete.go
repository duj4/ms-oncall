package graphqlapp

import (
	"context"
	"database/sql"
	"slices"

	"github.com/google/uuid"
	"github.com/target/goalert/validation/validate"
)

// deleteIntegrationKeys uses the DeleteAll transaction for both authorization
// and every scoped delete. A Human never reaches the Store's nil-scope path.
func (a *Mutation) deleteIntegrationKeys(ctx context.Context, tx *sql.Tx, ids []string) error {
	authority, err := integrationKeyManagementAuthority(ctx)
	if err != nil {
		return err
	}
	if authority.system {
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
		err := tx.QueryRowContext(ctx, `
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
	slices.Sort(organizations)
	for _, org := range organizations {
		scope := uuid.MustParse(org) // Only server-owned UUIDs enter this slice.
		if err := a.IntKeyStore.DeleteMany(ctx, tx, groups[scope], &scope); err != nil {
			return err
		}
	}
	return nil
}
