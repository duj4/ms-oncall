package contactmethod

import (
	"context"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/permission"
)

// RawVisible is independent of human administrative roles. System execution
// retains its existing internal delivery authority.
func (c ContactMethod) RawVisible(ctx context.Context) bool {
	return !c.Private || permission.System(ctx) || c.UserID == permission.UserID(ctx)
}

func (c ContactMethod) forViewer(ctx context.Context) *ContactMethod {
	if !c.RawVisible(ctx) {
		c.Dest.Args = map[string]string{}
	}
	return &c
}

// Human Organization scope is bound by the application from its admitted
// ExecutionContext. Stores do not reconstruct Session or requester authority.
func contactOrganizationScope(ctx context.Context, scope []*uuid.UUID) (uuid.NullUUID, error) {
	if len(scope) > 0 && scope[0] != nil {
		return uuid.NullUUID{UUID: *scope[0], Valid: true}, nil
	}
	if src := permission.Source(ctx); src != nil && src.Type == permission.SourceTypeAuthProvider {
		return uuid.NullUUID{}, permission.NewAccessDenied("Contact Method Organization scope is required")
	}
	return uuid.NullUUID{}, nil
}

// AuthorizeUser applies the domain boundary before private projection or
// mutation, including Users that currently have no Contact Methods.
func (s *Store) AuthorizeUser(ctx context.Context, db gadb.DBTX, userID string, scope ...*uuid.UUID) error {
	org, err := contactOrganizationScope(ctx, scope)
	if err != nil || !org.Valid {
		return err
	}
	var allowed bool
	err = db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM user_organization_assignments a JOIN normal_organizations n ON n.organization_id=a.effective_normal_organization_id WHERE a.user_id=$1 AND a.effective_organization_id=$2 AND a.effective_normal_organization_id=$2)`, userID, org).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return permission.NewAccessDenied("Contact Method is outside the authorized Organization")
	}
	return nil
}

func (s *Store) read(ctx context.Context, db gadb.DBTX, ids []uuid.UUID, userID uuid.NullUUID, scope []*uuid.UUID) ([]ContactMethod, error) {
	org, err := contactOrganizationScope(ctx, scope)
	if err != nil {
		return nil, err
	}
	// Ordinary reads project arguments in SQL before materializing a Contact
	// Method. Human administrative roles never grant raw-private visibility.
	query := `SELECT cm.id,cm.name,CASE WHEN $4 OR NOT cm.private OR cm.user_id=$5 THEN cm.dest ELSE jsonb_build_object('Type',cm.dest->>'Type','Args','{}'::jsonb) END,cm.disabled,cm.user_id,cm.pending,cm.private,cm.enable_status_updates,cm.last_test_verify_at
FROM user_contact_methods cm
WHERE (cm.id=ANY($1::uuid[]) OR cm.user_id=$2)
AND ($3::uuid IS NULL OR EXISTS(SELECT 1 FROM user_organization_assignments a JOIN normal_organizations n ON n.organization_id=a.effective_normal_organization_id WHERE a.user_id=cm.user_id AND a.effective_organization_id=$3 AND a.effective_normal_organization_id=$3))`
	rows, err := db.QueryContext(ctx, query, pq.Array(ids), userID, org, permission.System(ctx), permission.UserNullUUID(ctx))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ContactMethod, 0)
	for rows.Next() {
		var cm ContactMethod
		if err := rows.Scan(&cm.ID, &cm.Name, &cm.Dest, &cm.Disabled, &cm.UserID, &cm.Pending, &cm.Private, &cm.StatusUpdates, &cm.lastTestVerifyAt); err != nil {
			return nil, err
		}
		result = append(result, cm)
	}
	return result, rows.Err()
}

// FindOneForUpdate is the existing owner/Admin mutation read, with the existing
// row lock. Its raw destination is used to validate unchanged fields and is
// never returned as a GraphQL mutation result.
func (s *Store) FindOneForUpdate(ctx context.Context, db gadb.DBTX, id uuid.UUID, scope ...*uuid.UUID) (*ContactMethod, error) {
	if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
		return nil, err
	}
	org, err := contactOrganizationScope(ctx, scope)
	if err != nil {
		return nil, err
	}
	if org.Valid {
		var cm ContactMethod
		// Scope and existing mutation authority filter the row before a raw
		// mutation read or lock. A foreign UUID grants neither.
		err := db.QueryRowContext(ctx, `SELECT cm.id,cm.name,cm.dest,cm.disabled,cm.user_id,cm.pending,cm.private,cm.enable_status_updates,cm.last_test_verify_at
FROM user_contact_methods cm WHERE cm.id=$1 AND ($3 OR cm.user_id=$4)
AND EXISTS(SELECT 1 FROM user_organization_assignments a JOIN normal_organizations n ON n.organization_id=a.effective_normal_organization_id WHERE a.user_id=cm.user_id AND a.effective_organization_id=$2 AND a.effective_normal_organization_id=$2)
FOR UPDATE OF cm`, id, org, permission.Admin(ctx), permission.UserNullUUID(ctx)).Scan(&cm.ID, &cm.Name, &cm.Dest, &cm.Disabled, &cm.UserID, &cm.Pending, &cm.Private, &cm.StatusUpdates, &cm.lastTestVerifyAt)
		if err != nil {
			return nil, err
		}
		return &cm, nil
	}
	// Preserve the pre-existing non-human compatibility query, including its
	// destination-immutability and row-lock behavior.
	row, err := gadb.New(db).ContactMethodFindOneUpdate(ctx, id)
	if err != nil {
		return nil, err
	}
	cm := &ContactMethod{ID: row.ID, Name: row.Name, Dest: row.Dest.DestV1, Disabled: row.Disabled, UserID: row.UserID.String(), Pending: row.Pending, Private: row.Private, StatusUpdates: row.EnableStatusUpdates, lastTestVerifyAt: row.LastTestVerifyAt}

	if err := permission.LimitCheckAny(ctx, permission.Admin, permission.MatchUser(cm.UserID)); err != nil {
		return nil, err
	}
	return cm, nil
}

// DiagnosticTypeByID returns no addressing arguments, including for legacy
// historical message records whose tenancy is separately gated.
func (s *Store) DiagnosticTypeByID(ctx context.Context, db gadb.DBTX, id uuid.UUID) (string, error) {
	if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
		return "", err
	}
	var typ string
	err := db.QueryRowContext(ctx, `SELECT dest->>'Type' FROM user_contact_methods WHERE id=$1`, id).Scan(&typ)
	return typ, err
}
