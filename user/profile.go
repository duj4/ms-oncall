package user

import (
	"context"

	"github.com/google/uuid"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation/validate"
)

// FindManyInOrganization is the explicit GraphQL profile read. Generic
// FindMany/FindOne retain authentication and trusted internal compatibility.
// The application supplies its admitted Human Home, never a client scope.
func (s *Store) FindManyInOrganization(ctx context.Context, ids []string, organizationID uuid.UUID) ([]User, error) {
	if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
		return nil, err
	}
	if organizationID == uuid.Nil {
		return nil, permission.NewAccessDenied("User Organization scope is required")
	}
	if err := validate.ManyUUID("UserID", ids, 200); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT u.id,u.name,u.email,u.avatar_url,u.role,fav IS DISTINCT FROM NULL
		FROM users u
		LEFT JOIN user_favorites fav ON fav.tgt_user_id=u.id AND fav.user_id=$2
		WHERE u.id=ANY($1::uuid[]) AND EXISTS (
			SELECT 1 FROM user_organization_assignments a
			JOIN normal_organizations n ON n.organization_id=a.effective_normal_organization_id
			WHERE a.user_id=u.id AND a.effective_organization_id=$3
				AND a.effective_normal_organization_id=$3)`,
		sqlutil.UUIDArray(ids), permission.UserNullUUID(ctx), organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]User, 0, len(ids))
	for rows.Next() {
		var u User
		if err := u.scanFrom(rows.Scan); err != nil {
			return nil, err
		}
		result = append(result, u)
	}
	return result, rows.Err()
}
