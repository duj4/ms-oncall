package override

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation"
	"github.com/target/goalert/validation/validate"
)

// Store is used to manage active overrides.
type Store struct {
	db *sql.DB

	findUO    *sql.Stmt
	createUO  *sql.Stmt
	deleteUO  *sql.Stmt
	findAllUO *sql.Stmt
	updateUO  *sql.Stmt

	lock *sql.Stmt

	findUOUpdate             *sql.Stmt
	findScheduleOrganization *sql.Stmt
	findCreateUsers          *sql.Stmt
}

// NewStore initializes a new DB using an existing sql connection.
func NewStore(ctx context.Context, db *sql.DB) (*Store, error) {
	p := &util.Prepare{DB: db, Ctx: ctx}

	return &Store{
		db: db,

		lock: p.P(`LOCK user_overrides IN EXCLUSIVE MODE`),
		// Authorization must not lock the Schedule: Schedule deletion takes its
		// row lock before cascading to user_overrides.
		findScheduleOrganization: p.P(`select 1 from schedules where id = $1 and organization_id = $2`),
		findCreateUsers: p.P(`select
			exists (select 1 from users where id = $1),
			exists (select 1 from users where id = $2)`),

		findUOUpdate: p.P(`
		select
			id,
			add_user_id, 
			remove_user_id,
			start_time,
			end_time,
			tgt_schedule_id
		from user_overrides
		where id = $1 and ($2::uuid is null or exists (
			select 1 from schedules where id = user_overrides.tgt_schedule_id and organization_id = $2
		))
		for update
	`),
		findUO: p.P(`
			select
				id,
				add_user_id, 
				remove_user_id,
				start_time,
				end_time,
				tgt_schedule_id
			from user_overrides
			where id = $1 and ($2::uuid is null or exists (
				select 1 from schedules where id = user_overrides.tgt_schedule_id and organization_id = $2
			))
		`),
		updateUO: p.P(`
			update user_overrides
			set
				add_user_id = $2,
				remove_user_id = $3,
				start_time = $4,
				end_time = $5,
				tgt_schedule_id = $6
			where id = $1 and ($7::uuid is null or (
				tgt_schedule_id = $6 and exists (
					select 1 from schedules where id = user_overrides.tgt_schedule_id and organization_id = $7
				)
			))
		`),
		createUO: p.P(`
			insert into user_overrides (
				id,
				add_user_id,
				remove_user_id,
				start_time,
				end_time,
				tgt_schedule_id
			) values ($1, $2, $3, $4, $5, $6)`),
		deleteUO: p.P(`delete from user_overrides where id = any($1) and ($2::uuid is null or exists (
			select 1 from schedules where id = user_overrides.tgt_schedule_id and organization_id = $2
		))`),
		findAllUO: p.P(`
			select
				id,
				add_user_id, 
				remove_user_id,
				start_time,
				end_time
			from user_overrides
			where
				tgt_schedule_id = $1 and
				(start_time, end_time) OVERLAPS ($2, $3)
		`),
	}, p.Err
}

func (s *Store) withTx(ctx context.Context, tx *sql.Tx, fn func(tx *sql.Tx) error) error {
	if tx == nil {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		// Since this is a helper method, we don't
		// have much context to work with.
		defer sqlutil.Rollback(ctx, "override", tx)

		err = s.withTx(ctx, tx, fn)
		if err != nil {
			return err
		}
		return tx.Commit()
	}

	_, err := tx.StmtContext(ctx, s.lock).ExecContext(ctx)
	if err != nil {
		return err
	}

	return fn(tx)
}

func (s *Store) execContext(ctx context.Context, tx *sql.Tx, stmt *sql.Stmt, args ...interface{}) error {
	return s.withTx(ctx, tx, func(tx *sql.Tx) error {
		_, err := tx.StmtContext(ctx, stmt).ExecContext(ctx, args...)
		return err
	})
}

func (s *Store) FindOneUserOverrideTx(ctx context.Context, tx *sql.Tx, id string, forUpdate bool) (*UserOverride, error) {
	return s.FindOneUserOverrideTxScoped(ctx, tx, id, forUpdate, nil)
}

// FindOneUserOverrideTxScoped resolves ownership through the persisted Schedule.
// A nil Organization retains the existing non-human compatibility behavior.
func (s *Store) FindOneUserOverrideTxScoped(ctx context.Context, tx *sql.Tx, id string, forUpdate bool, organizationID *uuid.UUID) (*UserOverride, error) {
	err := permission.LimitCheckAny(ctx, permission.User, permission.Admin)
	if err != nil {
		return nil, err
	}
	err = validate.UUID("OverrideID", id)
	if err != nil {
		return nil, err
	}
	scope, err := organizationScope(organizationID)
	if err != nil {
		return nil, err
	}

	var o UserOverride
	var add, rem, schedTgt sql.NullString
	err = s.withTx(ctx, tx, func(tx *sql.Tx) error {
		var row *sql.Row
		if forUpdate {
			row = tx.StmtContext(ctx, s.findUOUpdate).QueryRowContext(ctx, id, scope)
		} else {
			row = tx.StmtContext(ctx, s.findUO).QueryRowContext(ctx, id, scope)
		}

		return row.Scan(&o.ID, &add, &rem, &o.Start, &o.End, &schedTgt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	o.AddUserID = add.String
	o.RemoveUserID = rem.String
	if schedTgt.Valid {
		o.Target = assignment.ScheduleTarget(schedTgt.String)
	}

	return &o, nil
}

// UpdateUserOverrideTx updates an existing UserOverride, inside an optional transaction.
func (s *Store) UpdateUserOverrideTx(ctx context.Context, tx *sql.Tx, o *UserOverride) error {
	return s.UpdateUserOverrideTxScoped(ctx, tx, o, nil)
}

// UpdateUserOverrideTxScoped authorizes the persisted parent and does not allow
// a scoped update to reparent an override using a submitted Target.
func (s *Store) UpdateUserOverrideTxScoped(ctx context.Context, tx *sql.Tx, o *UserOverride, organizationID *uuid.UUID) error {
	err := permission.LimitCheckAny(ctx, permission.User, permission.Admin)
	if err != nil {
		return err
	}
	n, err := o.Normalize()
	if err != nil {
		return err
	}
	err = validate.UUID("ID", n.ID)
	if err != nil {
		return err
	}
	if !n.End.After(time.Now()) {
		return validation.NewFieldError("End", "must be in the future")
	}
	scope, err := organizationScope(organizationID)
	if err != nil {
		return err
	}
	var add, rem sql.NullString
	if n.AddUserID != "" {
		add.Valid = true
		add.String = n.AddUserID
	}
	if n.RemoveUserID != "" {
		rem.Valid = true
		rem.String = n.RemoveUserID
	}
	var schedTgt sql.NullString
	if n.Target.TargetType() == assignment.TargetTypeSchedule {
		schedTgt.Valid = true
		schedTgt.String = n.Target.TargetID()
	}
	return s.withTx(ctx, tx, func(tx *sql.Tx) error {
		result, err := tx.StmtContext(ctx, s.updateUO).ExecContext(ctx, n.ID, add, rem, n.Start, n.End, schedTgt, scope)
		if err != nil || organizationID == nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return validation.NewFieldError("ID", "user override not found")
		}
		return nil
	})
}

// UpdateUserOverride updates an existing UserOverride.
func (s *Store) UpdateUserOverride(ctx context.Context, o *UserOverride) error {
	return s.UpdateUserOverrideTx(ctx, nil, o)
}

// CreateUserOverrideTx adds a UserOverride to the DB with a new ID.
func (s *Store) CreateUserOverrideTx(ctx context.Context, tx *sql.Tx, o *UserOverride) (*UserOverride, error) {
	return s.CreateUserOverrideTxScoped(ctx, tx, o, nil)
}

// CreateUserOverrideTxScoped checks Schedule ownership in the same transaction,
// after local validation and before insertion can expose conflict state.
func (s *Store) CreateUserOverrideTxScoped(ctx context.Context, tx *sql.Tx, o *UserOverride, organizationID *uuid.UUID) (*UserOverride, error) {
	err := permission.LimitCheckAny(ctx, permission.User, permission.Admin)
	if err != nil {
		return nil, err
	}
	n, err := o.Normalize()
	if err != nil {
		return nil, err
	}
	if !n.End.After(time.Now()) {
		return nil, validation.NewFieldError("End", "must be in the future")
	}
	scope, err := organizationScope(organizationID)
	if err != nil {
		return nil, err
	}
	n.ID = uuid.New().String()
	var add, rem sql.NullString
	if n.AddUserID != "" {
		add.Valid = true
		add.String = n.AddUserID
	}
	if n.RemoveUserID != "" {
		rem.Valid = true
		rem.String = n.RemoveUserID
	}
	var schedTgt sql.NullString
	if n.Target.TargetType() == assignment.TargetTypeSchedule {
		schedTgt.Valid = true
		schedTgt.String = n.Target.TargetID()
	}
	err = s.withTx(ctx, tx, func(tx *sql.Tx) error {
		if scope.Valid {
			// Preserve the existing CHECK, then Add/Remove User FK validation
			// precedence. These checks expose no Schedule or override state.
			if add.Valid && rem.Valid && uuid.MustParse(add.String) == uuid.MustParse(rem.String) {
				return validation.NewFieldError("AddUserID", "cannot be the same as the user being replaced")
			}
			var addExists, removeExists bool
			err := tx.StmtContext(ctx, s.findCreateUsers).QueryRowContext(ctx, add, rem).Scan(&addExists, &removeExists)
			if err != nil {
				return err
			}
			if add.Valid && !addExists {
				return validation.NewFieldError("AddUserID", "user does not exist")
			}
			if rem.Valid && !removeExists {
				return validation.NewFieldError("RemoveUserID", "user does not exist")
			}
			// Both identity and parent lookups are non-locking. Insertion still
			// enforces FKs and checks conflicts only after parent authorization.
			var found int
			err = tx.StmtContext(ctx, s.findScheduleOrganization).QueryRowContext(ctx, schedTgt, scope).Scan(&found)
			if errors.Is(err, sql.ErrNoRows) {
				return validation.NewFieldError("TargetID", "schedule does not exist")
			}
			if err != nil {
				return err
			}
		}
		_, err := tx.StmtContext(ctx, s.createUO).ExecContext(ctx, n.ID, add, rem, n.Start, n.End, schedTgt)
		return err
	})
	if err != nil {
		return nil, err
	}

	return n, nil
}

// DeleteUserOverride removes a UserOverride from the DB matching the given ID.
func (s *Store) DeleteUserOverrideTx(ctx context.Context, tx *sql.Tx, ids ...string) error {
	return s.DeleteUserOverrideTxScoped(ctx, tx, ids, nil)
}

// DeleteUserOverrideTxScoped requires every distinct requested override to be
// owned. Callers supplying a transaction must roll it back on error.
func (s *Store) DeleteUserOverrideTxScoped(ctx context.Context, tx *sql.Tx, ids []string, organizationID *uuid.UUID) error {
	err := permission.LimitCheckAny(ctx, permission.User, permission.Admin)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	err = validate.ManyUUID("UserOverrideID", ids, 50)
	if err != nil {
		return err
	}
	scope, err := organizationScope(organizationID)
	if err != nil {
		return err
	}

	return s.withTx(ctx, tx, func(tx *sql.Tx) error {
		result, err := tx.StmtContext(ctx, s.deleteUO).ExecContext(ctx, sqlutil.UUIDArray(ids), scope)
		if err != nil || organizationID == nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		want := make(map[uuid.UUID]struct{}, len(ids))
		for _, id := range ids {
			want[uuid.MustParse(id)] = struct{}{}
		}
		if count != int64(len(want)) {
			return sql.ErrNoRows
		}
		return nil
	})
}

func organizationScope(organizationID *uuid.UUID) (uuid.NullUUID, error) {
	if organizationID == nil {
		return uuid.NullUUID{}, nil
	}
	if *organizationID == uuid.Nil {
		return uuid.NullUUID{}, validation.NewFieldError("OrganizationID", "must be specified")
	}
	return uuid.NullUUID{UUID: *organizationID, Valid: true}, nil
}

// FindAllUserOverrides will return all UserOverrides that belong to the provided Target within the provided time range.
func (s *Store) FindAllUserOverrides(ctx context.Context, start, end time.Time, t assignment.Target) ([]UserOverride, error) {
	err := permission.LimitCheckAny(ctx, permission.User, permission.Admin)
	if err != nil {
		return nil, err
	}
	err = validate.Many(
		validate.OneOf("TargetType", t.TargetType(), assignment.TargetTypeSchedule),
		validate.UUID("TargetID", t.TargetID()),
	)
	if err != nil {
		return nil, err
	}

	var schedTgt sql.NullString
	if t.TargetType() == assignment.TargetTypeSchedule {
		schedTgt.Valid = true
		schedTgt.String = t.TargetID()
	}

	rows, err := s.findAllUO.QueryContext(ctx, schedTgt, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []UserOverride
	var o UserOverride
	var add, rem sql.NullString
	o.Target = t
	for rows.Next() {
		err = rows.Scan(&o.ID, &add, &rem, &o.Start, &o.End)
		if err != nil {
			return nil, err
		}
		// no need to check `Valid` since we're find with the empty string
		o.AddUserID = add.String
		o.RemoveUserID = rem.String
		result = append(result, o)
	}

	return result, nil
}
