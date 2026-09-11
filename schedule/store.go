package schedule

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/user"
	"github.com/target/goalert/util"
	"github.com/target/goalert/validation"
	"github.com/target/goalert/validation/validate"
)

type Store struct {
	db  *sql.DB
	usr *user.Store
}

func NewStore(ctx context.Context, db *sql.DB, usr *user.Store) (*Store, error) {
	return &Store{
		db:  db,
		usr: usr,
	}, nil
}

func (store *Store) FindManyTx(ctx context.Context, tx *sql.Tx, ids []string, organizationID *uuid.UUID) ([]Schedule, error) {
	err := permission.LimitCheckAny(ctx, permission.All)
	if err != nil {
		return nil, err
	}
	err = validate.ManyUUID("ScheduleID", ids, 200)
	if err != nil {
		return nil, err
	}

	// Convert string IDs to UUIDs
	uuids := make([]uuid.UUID, len(ids))
	for i, id := range ids {
		uuids[i], err = uuid.Parse(id)
		if err != nil {
			return nil, err
		}
	}

	db := gadb.New(store.db)
	if tx != nil {
		db = db.WithTx(tx)
	}

	var result []Schedule
	if organizationID != nil {
		if *organizationID == uuid.Nil {
			return nil, validation.NewFieldError("OrganizationID", "must be specified")
		}
		rows, err := db.SchedFindManyScoped(ctx, gadb.SchedFindManyScopedParams{
			Column1:        uuids,
			UserID:         permission.UserNullUUID(ctx).UUID,
			OrganizationID: *organizationID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		result = make([]Schedule, 0, len(ids))
		for _, row := range rows {
			s := Schedule{
				ID:             row.ID.String(),
				OrganizationID: row.OrganizationID,
				Name:           row.Name,
				Description:    row.Description,
				isUserFavorite: row.IsFavorite,
			}
			s.TimeZone, err = util.LoadLocation(row.TimeZone)
			if err != nil {
				return nil, err
			}
			result = append(result, s)
		}
		return result, nil
	}

	rows, err := db.SchedFindMany(ctx, gadb.SchedFindManyParams{
		Column1: uuids,
		UserID:  permission.UserNullUUID(ctx).UUID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	result = make([]Schedule, 0, len(ids))
	for _, row := range rows {
		s := Schedule{
			ID:             row.ID.String(),
			OrganizationID: row.OrganizationID,
			Name:           row.Name,
			Description:    row.Description,
			isUserFavorite: row.IsFavorite,
		}

		s.TimeZone, err = util.LoadLocation(row.TimeZone)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}

	return result, nil
}

func (store *Store) FindMany(ctx context.Context, ids []string, organizationID *uuid.UUID) ([]Schedule, error) {
	return store.FindManyTx(ctx, nil, ids, organizationID)
}

func (store *Store) FindManyByUserID(ctx context.Context, db gadb.DBTX, userID uuid.NullUUID, organizationID *uuid.UUID) ([]Schedule, error) {
	err := permission.LimitCheckAny(ctx, permission.All)
	if err != nil {
		return nil, err
	}

	queries := gadb.New(db)
	var rows []gadb.Schedule
	if organizationID == nil {
		rows, err = queries.ScheduleFindManyByUser(ctx, userID)
	} else {
		if *organizationID == uuid.Nil {
			return nil, validation.NewFieldError("OrganizationID", "must be specified")
		}
		rows, err = queries.ScheduleFindManyByUserScoped(ctx, gadb.ScheduleFindManyByUserScopedParams{
			TgtUserID:      userID,
			OrganizationID: *organizationID,
		})
	}

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var result []Schedule
	for _, r := range rows {
		result = append(result, Schedule{
			ID:             r.ID.String(),
			OrganizationID: r.OrganizationID,
			Name:           r.Name,
			Description:    r.Description,
		})
	}

	return result, nil
}

func (store *Store) Create(ctx context.Context, s *Schedule) (*Schedule, error) {
	return store.CreateScheduleTx(ctx, nil, s)
}

func (store *Store) CreateScheduleTx(ctx context.Context, tx *sql.Tx, s *Schedule) (*Schedule, error) {
	n, err := s.Normalize()
	if err != nil {
		return nil, err
	}

	err = permission.LimitCheckAny(ctx, permission.Admin, permission.User)
	if err != nil {
		return nil, err
	}
	if n.OrganizationID == uuid.Nil {
		return nil, validation.NewFieldError("OrganizationID", "must be specified")
	}

	db := gadb.New(store.db)
	if tx != nil {
		db = db.WithTx(tx)
	}

	id, err := db.SchedCreate(ctx, gadb.SchedCreateParams{
		OrganizationID: n.OrganizationID,
		Name:           n.Name,
		Description:    n.Description,
		TimeZone:       n.TimeZone.String(),
	})
	if err != nil {
		return nil, err
	}

	n.ID = id.String()
	return n, nil
}

func (store *Store) Update(ctx context.Context, s *Schedule) error {
	return store.update(ctx, nil, s, nil)
}

func (store *Store) update(ctx context.Context, tx *sql.Tx, s *Schedule, organizationID *uuid.UUID) error {
	n, err := s.Normalize()
	if err != nil {
		return err
	}

	err = validate.UUID("ScheduleID", s.ID)
	if err != nil {
		return err
	}

	err = permission.LimitCheckAny(ctx, permission.Admin, permission.User)
	if err != nil {
		return err
	}

	id, err := uuid.Parse(n.ID)
	if err != nil {
		return err
	}

	db := gadb.New(store.db)
	if tx != nil {
		db = db.WithTx(tx)
	}
	if organizationID == nil {
		return db.SchedUpdate(ctx, gadb.SchedUpdateParams{
			ID:          id,
			Name:        n.Name,
			Description: n.Description,
			TimeZone:    n.TimeZone.String(),
		})
	}
	if *organizationID == uuid.Nil {
		return validation.NewFieldError("OrganizationID", "must be specified")
	}
	rows, err := db.SchedUpdateScoped(ctx, gadb.SchedUpdateScopedParams{
		ID:             id,
		Name:           n.Name,
		Description:    n.Description,
		TimeZone:       n.TimeZone.String(),
		OrganizationID: *organizationID,
	})
	if err != nil {
		return err
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (store *Store) UpdateTx(ctx context.Context, tx *sql.Tx, s *Schedule, organizationID *uuid.UUID) error {
	return store.update(ctx, tx, s, organizationID)
}

func (store *Store) FindAll(ctx context.Context) ([]Schedule, error) {
	err := permission.LimitCheckAny(ctx, permission.All)
	if err != nil {
		return nil, err
	}

	rows, err := gadb.New(store.db).SchedFindAll(ctx)
	if err != nil {
		return nil, err
	}

	var res []Schedule
	for _, row := range rows {
		s := Schedule{
			ID:             row.ID.String(),
			OrganizationID: row.OrganizationID,
			Name:           row.Name,
			Description:    row.Description,
		}
		s.TimeZone, err = util.LoadLocation(row.TimeZone)
		if err != nil {
			return nil, errors.Wrap(err, "parse scanned time zone")
		}
		res = append(res, s)
	}

	return res, nil
}

func (store *Store) FindOneForUpdate(ctx context.Context, tx *sql.Tx, id string, organizationID *uuid.UUID) (*Schedule, error) {
	err := permission.LimitCheckAny(ctx, permission.All)
	if err != nil {
		return nil, err
	}
	err = validate.UUID("ScheduleID", id)
	if err != nil {
		return nil, err
	}

	schedID, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}

	db := gadb.New(store.db)
	if tx != nil {
		db = db.WithTx(tx)
	}

	var s Schedule
	var timeZone string
	if organizationID == nil {
		row, err := db.SchedFindOneForUpdate(ctx, schedID)
		if err != nil {
			return nil, err
		}
		s.ID = row.ID.String()
		s.OrganizationID = row.OrganizationID
		s.Name = row.Name
		s.Description = row.Description
		timeZone = row.TimeZone
	} else {
		if *organizationID == uuid.Nil {
			return nil, validation.NewFieldError("OrganizationID", "must be specified")
		}
		row, err := db.SchedFindOneForUpdateScoped(ctx, gadb.SchedFindOneForUpdateScopedParams{
			ID:             schedID,
			OrganizationID: *organizationID,
		})
		if err != nil {
			return nil, err
		}
		s.ID = row.ID.String()
		s.OrganizationID = row.OrganizationID
		s.Name = row.Name
		s.Description = row.Description
		timeZone = row.TimeZone
	}

	s.TimeZone, err = util.LoadLocation(timeZone)
	if err != nil {
		return nil, err
	}

	return &s, nil
}

func (store *Store) FindOne(ctx context.Context, id string, organizationID *uuid.UUID) (*Schedule, error) {
	err := validate.UUID("ScheduleID", id)
	if err != nil {
		return nil, err
	}
	err = permission.LimitCheckAny(ctx, permission.All)
	if err != nil {
		return nil, err
	}

	schedID, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}

	db := gadb.New(store.db)
	var s Schedule
	var timeZone string
	if organizationID == nil {
		row, err := db.SchedFindOne(ctx, gadb.SchedFindOneParams{
			ID:     schedID,
			UserID: permission.UserNullUUID(ctx).UUID,
		})
		if err != nil {
			return nil, err
		}
		s.ID = row.ID.String()
		s.OrganizationID = row.OrganizationID
		s.Name = row.Name
		s.Description = row.Description
		s.isUserFavorite = row.IsFavorite
		timeZone = row.TimeZone
	} else {
		if *organizationID == uuid.Nil {
			return nil, validation.NewFieldError("OrganizationID", "must be specified")
		}
		row, err := db.SchedFindOneScoped(ctx, gadb.SchedFindOneScopedParams{
			ID:             schedID,
			UserID:         permission.UserNullUUID(ctx).UUID,
			OrganizationID: *organizationID,
		})
		if err != nil {
			return nil, err
		}
		s.ID = row.ID.String()
		s.OrganizationID = row.OrganizationID
		s.Name = row.Name
		s.Description = row.Description
		s.isUserFavorite = row.IsFavorite
		timeZone = row.TimeZone
	}

	s.TimeZone, err = util.LoadLocation(timeZone)
	if err != nil {
		return nil, err
	}

	return &s, nil
}

func (store *Store) Delete(ctx context.Context, id string, organizationID *uuid.UUID) error {
	return store.DeleteTx(ctx, nil, id, organizationID)
}

func (store *Store) DeleteTx(ctx context.Context, tx *sql.Tx, id string, organizationID *uuid.UUID) error {
	return store.DeleteManyTx(ctx, tx, []string{id}, organizationID)
}

func (store *Store) DeleteManyTx(ctx context.Context, tx *sql.Tx, ids []string, organizationID *uuid.UUID) error {
	err := permission.LimitCheckAny(ctx, permission.Admin, permission.User)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	err = validate.ManyUUID("ScheduleID", ids, 50)
	if err != nil {
		return err
	}

	// Convert string IDs to UUIDs
	uuids := make([]uuid.UUID, len(ids))
	for i, id := range ids {
		uuids[i], err = uuid.Parse(id)
		if err != nil {
			return err
		}
	}

	db := gadb.New(store.db)
	if tx != nil {
		db = db.WithTx(tx)
	}

	if organizationID == nil {
		return db.SchedDeleteMany(ctx, uuids)
	}
	if *organizationID == uuid.Nil {
		return validation.NewFieldError("OrganizationID", "must be specified")
	}
	rows, err := db.SchedDeleteManyScoped(ctx, gadb.SchedDeleteManyScopedParams{
		Column1:        uuids,
		OrganizationID: *organizationID,
	})
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
