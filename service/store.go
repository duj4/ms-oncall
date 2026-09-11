package service

import (
	"context"
	"database/sql"

	"github.com/target/goalert/permission"
	"github.com/target/goalert/util"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation"
	"github.com/target/goalert/validation/validate"

	"github.com/google/uuid"
)

type Store struct {
	db *sql.DB

	findOne        *sql.Stmt
	findOneOrg     *sql.Stmt
	findOneUp      *sql.Stmt
	findOneUpOrg   *sql.Stmt
	findMany       *sql.Stmt
	findManyOrg    *sql.Stmt
	findAllByEP    *sql.Stmt
	findAllByEPOrg *sql.Stmt
	insert         *sql.Stmt
	update         *sql.Stmt
	updateOrg      *sql.Stmt
	delete         *sql.Stmt
	deleteOrg      *sql.Stmt
}

func NewStore(ctx context.Context, db *sql.DB) (*Store, error) {
	prep := &util.Prepare{DB: db, Ctx: ctx}
	p := prep.P

	s := &Store{db: db}
	s.findOne = p(`
		SELECT
			s.id,
			s.organization_id,
			s.name,
			s.description,
			s.escalation_policy_id,
			e.name,
			fav	is distinct from null,
			s.maintenance_expires_at
		FROM
			services s
		JOIN escalation_policies e ON e.id = s.escalation_policy_id
		LEFT JOIN user_favorites fav ON s.id = fav.tgt_service_id AND fav.user_id = $2
		WHERE
			s.id = $1
	`)
	s.findOneOrg = p(`
		SELECT
			s.id,
			s.organization_id,
			s.name,
			s.description,
			s.escalation_policy_id,
			e.name,
			fav is distinct from null,
			s.maintenance_expires_at
		FROM
			services s
		JOIN escalation_policies e ON e.id = s.escalation_policy_id
		LEFT JOIN user_favorites fav ON s.id = fav.tgt_service_id AND fav.user_id = $2
		WHERE
			s.id = $1 AND
			s.organization_id = $3
	`)
	s.findOneUp = p(`
		SELECT
			s.id,
			s.organization_id,
			s.name,
			s.description,
			s.escalation_policy_id
		FROM services s
		WHERE s.id = $1
		FOR UPDATE
	`)
	s.findOneUpOrg = p(`
		SELECT
			s.id,
			s.organization_id,
			s.name,
			s.description,
			s.escalation_policy_id
		FROM services s
		WHERE s.id = $1 AND s.organization_id = $2
		FOR UPDATE
	`)
	s.findMany = p(`
		SELECT
			s.id,
			s.organization_id,
			s.name,
			s.description,
			s.escalation_policy_id,
			e.name,
			fav	is distinct from null,
			s.maintenance_expires_at
		FROM
			services s
		JOIN escalation_policies e ON e.id = s.escalation_policy_id
		LEFT JOIN user_favorites fav ON s.id = fav.tgt_service_id AND fav.user_id = $2
		WHERE
			s.id = any($1)
	`)
	s.findManyOrg = p(`
		SELECT
			s.id,
			s.organization_id,
			s.name,
			s.description,
			s.escalation_policy_id,
			e.name,
			fav is distinct from null,
			s.maintenance_expires_at
		FROM
			services s
		JOIN escalation_policies e ON e.id = s.escalation_policy_id
		LEFT JOIN user_favorites fav ON s.id = fav.tgt_service_id AND fav.user_id = $2
		WHERE
			s.id = any($1) AND
			s.organization_id = $3
	`)

	s.findAllByEP = p(`
		SELECT
			s.id,
			s.organization_id,
			s.name,
			s.description,
			s.escalation_policy_id,
			e.name,
			false,
			s.maintenance_expires_at
		FROM
			services s,
			escalation_policies e
		WHERE
			e.id = $1 AND
			e.id = s.escalation_policy_id
	`)
	s.findAllByEPOrg = p(`
		SELECT
			s.id,
			s.organization_id,
			s.name,
			s.description,
			s.escalation_policy_id,
			e.name,
			false,
			s.maintenance_expires_at
		FROM
			services s,
			escalation_policies e
		WHERE
			e.id = $1 AND
			e.id = s.escalation_policy_id AND
			s.organization_id = $2
	`)
	s.insert = p(`INSERT INTO services (id,organization_id,name,description,escalation_policy_id) VALUES ($1,$2,$3,$4,$5)`)
	s.update = p(`UPDATE services SET name = $2, description = $3, escalation_policy_id = $4, maintenance_expires_at = $5 WHERE id = $1`)
	s.updateOrg = p(`UPDATE services SET name = $2, description = $3, escalation_policy_id = $4, maintenance_expires_at = $5 WHERE id = $1 AND organization_id = $6`)
	s.delete = p(`DELETE FROM services WHERE id = any($1)`)
	s.deleteOrg = p(`
		DELETE FROM services s
		WHERE s.id = any($1)
			AND s.organization_id = $2
			AND (
				SELECT count(*)
				FROM (
					SELECT DISTINCT requested_id
					FROM unnest($1::uuid[]) AS requested(requested_id)
				) requested
			) = (
				SELECT count(*)
				FROM services matched
				WHERE matched.id = any($1)
					AND matched.organization_id = $2
			)
	`)

	return s, prep.Err
}

func (s *Store) FindOneForUpdate(ctx context.Context, tx *sql.Tx, id string, organizationID *uuid.UUID) (*Service, error) {
	err := permission.LimitCheckAny(ctx, permission.User)
	if err != nil {
		return nil, err
	}
	err = validate.UUID("ServiceID", id)
	if err != nil {
		return nil, err
	}
	stmt := s.findOneUp
	args := []any{id}
	if organizationID != nil {
		if *organizationID == uuid.Nil {
			return nil, validation.NewFieldError("OrganizationID", "must be specified")
		}
		stmt = s.findOneUpOrg
		args = append(args, *organizationID)
	}
	if tx != nil {
		stmt = tx.StmtContext(ctx, stmt)
	}

	var svc Service
	err = stmt.QueryRowContext(ctx, args...).Scan(
		&svc.ID,
		&svc.OrganizationID,
		&svc.Name,
		&svc.Description,
		&svc.EscalationPolicyID,
	)
	if err != nil {
		return nil, err
	}
	return &svc, nil
}

// FindMany returns slice of Service objects given a slice of serviceIDs
func (s *Store) FindMany(ctx context.Context, ids []string, organizationID *uuid.UUID) ([]Service, error) {
	err := permission.LimitCheckAny(ctx, permission.User)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	err = validate.ManyUUID("ServiceIDs", ids, 100)
	if err != nil {
		return nil, err
	}

	stmt := s.findMany
	args := []any{sqlutil.UUIDArray(ids), permission.UserNullUUID(ctx)}
	if organizationID != nil {
		if *organizationID == uuid.Nil {
			return nil, validation.NewFieldError("OrganizationID", "must be specified")
		}
		stmt = s.findManyOrg
		args = append(args, *organizationID)
	}
	rows, err := stmt.QueryContext(ctx, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAllFrom(rows)
}

func (s *Store) CreateServiceTx(ctx context.Context, tx *sql.Tx, svc *Service) (*Service, error) {
	err := permission.LimitCheckAny(ctx, permission.Admin, permission.User)
	if err != nil {
		return nil, err
	}
	n, err := svc.Normalize()
	if err != nil {
		return nil, err
	}
	if n.OrganizationID == uuid.Nil {
		return nil, validation.NewFieldError("OrganizationID", "must be specified")
	}

	n.ID = uuid.New().String()
	stmt := s.insert
	if tx != nil {
		stmt = tx.Stmt(stmt)
	}
	_, err = stmt.ExecContext(ctx, n.ID, n.OrganizationID, n.Name, n.Description, n.EscalationPolicyID)
	if err != nil {
		return nil, err
	}

	return n, nil
}

func (s *Store) DeleteManyTx(ctx context.Context, tx *sql.Tx, ids []string, organizationID *uuid.UUID) error {
	err := permission.LimitCheckAny(ctx, permission.Admin, permission.User)
	if err != nil {
		return err
	}
	err = validate.ManyUUID("ServiceID", ids, 50)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	stmt := s.delete
	args := []any{sqlutil.UUIDArray(ids)}
	if organizationID != nil {
		if *organizationID == uuid.Nil {
			return validation.NewFieldError("OrganizationID", "must be specified")
		}
		stmt = s.deleteOrg
		args = append(args, *organizationID)
	}
	if tx != nil {
		stmt = tx.StmtContext(ctx, stmt)
	}
	result, err := stmt.ExecContext(ctx, args...)
	if err != nil || organizationID == nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	want := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		want[id] = struct{}{}
	}
	if rows != int64(len(want)) {
		return sql.ErrNoRows
	}
	return nil
}

func wrap(tx *sql.Tx, s *sql.Stmt) *sql.Stmt {
	if tx == nil {
		return s
	}
	return tx.Stmt(s)
}

func (s *Store) UpdateTx(ctx context.Context, tx *sql.Tx, svc *Service, organizationID *uuid.UUID) error {
	err := permission.LimitCheckAny(ctx, permission.Admin, permission.User)
	if err != nil {
		return err
	}

	n, err := svc.Normalize()
	if err != nil {
		return err
	}

	err = validate.UUID("ServiceID", n.ID)
	if err != nil {
		return err
	}

	mExp := sql.NullTime{
		Time:  n.MaintenanceExpiresAt,
		Valid: !n.MaintenanceExpiresAt.IsZero(),
	}

	stmt := s.update
	args := []any{n.ID, n.Name, n.Description, n.EscalationPolicyID, mExp}
	if organizationID != nil {
		if *organizationID == uuid.Nil {
			return validation.NewFieldError("OrganizationID", "must be specified")
		}
		stmt = s.updateOrg
		args = append(args, *organizationID)
	}
	result, err := wrap(tx, stmt).ExecContext(ctx, args...)
	if err != nil || organizationID == nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) FindOneForUser(ctx context.Context, userID, serviceID string, organizationID *uuid.UUID) (*Service, error) {
	err := validate.UUID("ServiceID", serviceID)
	if err != nil {
		return nil, err
	}

	var uid sql.NullString
	userCheck := permission.User

	if userID != "" {
		err := validate.UUID("UserID", userID)
		if err != nil {
			return nil, err
		}
		userCheck = permission.MatchUser(userID)
		uid.Valid = true
		uid.String = userID
	}

	err = permission.LimitCheckAny(ctx, userCheck, permission.System)
	if err != nil {
		return nil, err
	}

	stmt := s.findOne
	args := []any{serviceID, uid}
	if organizationID != nil {
		if *organizationID == uuid.Nil {
			return nil, validation.NewFieldError("OrganizationID", "must be specified")
		}
		stmt = s.findOneOrg
		args = append(args, *organizationID)
	}
	row := stmt.QueryRowContext(ctx, args...)
	var svc Service
	err = scanFrom(&svc, row.Scan)
	if err != nil {
		return nil, err
	}

	return &svc, nil
}

func (s *Store) FindOne(ctx context.Context, id string, organizationID *uuid.UUID) (*Service, error) {
	// old method just calls new method
	return s.FindOneForUser(ctx, "", id, organizationID)
}

func scanFrom(s *Service, f func(args ...interface{}) error) error {
	var maintExpiresAt sql.NullTime
	err := f(
		&s.ID,
		&s.OrganizationID,
		&s.Name,
		&s.Description,
		&s.EscalationPolicyID,
		&s.epName,
		&s.isUserFavorite,
		&maintExpiresAt,
	)
	if err != nil {
		return err
	}
	s.MaintenanceExpiresAt = maintExpiresAt.Time
	return nil
}

func scanAllFrom(rows *sql.Rows) (services []Service, err error) {
	var s Service
	for rows.Next() {
		err = scanFrom(&s, rows.Scan)
		if err != nil {
			return nil, err
		}
		services = append(services, s)
	}
	return services, nil
}

func (s *Store) FindAllByEP(ctx context.Context, epID string, organizationID *uuid.UUID) ([]Service, error) {
	err := permission.LimitCheckAny(ctx, permission.Admin, permission.User)
	if err != nil {
		return nil, err
	}

	stmt := s.findAllByEP
	args := []any{epID}
	if organizationID != nil {
		if *organizationID == uuid.Nil {
			return nil, validation.NewFieldError("OrganizationID", "must be specified")
		}
		stmt = s.findAllByEPOrg
		args = append(args, *organizationID)
	}
	rows, err := stmt.QueryContext(ctx, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAllFrom(rows)
}
