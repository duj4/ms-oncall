package contactmethod

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/notification/nfydest"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/validation"
	"github.com/target/goalert/validation/validate"
)

// Store implements the lookup and management of ContactMethods against a *sql.Store backend.
type Store struct {
	reg *nfydest.Registry
}

func NewStore(reg *nfydest.Registry) *Store {
	return &Store{reg: reg}
}

func (s *Store) MetadataByDest(ctx context.Context, dbtx gadb.DBTX, dest gadb.DestV1) (*Metadata, error) {
	err := permission.LimitCheckAny(ctx, permission.Admin)
	if err != nil {
		return nil, err
	}

	data, err := gadb.New(dbtx).ContactMethodMetaDest(ctx, gadb.NullDestV1{Valid: true, DestV1: dest})
	if err != nil {
		return nil, err
	}

	var m Metadata
	err = json.Unmarshal(data.Metadata, &m)
	if err != nil {
		return nil, err
	}
	m.FetchedAt = data.Now

	return &m, nil
}

func (s *Store) SetCarrierV1MetadataByDest(ctx context.Context, dbtx gadb.DBTX, dest gadb.DestV1, newM *Metadata) error {
	err := permission.LimitCheckAny(ctx, permission.Admin)
	if err != nil {
		return err
	}

	data, err := json.Marshal(newM.CarrierV1)
	if err != nil {
		return err
	}

	err = gadb.New(dbtx).ContactMethodUpdateMetaDest(ctx, gadb.ContactMethodUpdateMetaDestParams{Dest: gadb.NullDestV1{Valid: true, DestV1: dest}, CarrierV1: data})
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) FindDestByID(ctx context.Context, tx gadb.DBTX, id uuid.UUID, scope ...*uuid.UUID) (gadb.DestV1, error) {
	err := permission.LimitCheckAny(ctx, permission.User)
	if err != nil {
		return gadb.DestV1{}, err
	}

	cm, err := s.FindOne(ctx, tx, id, scope...)
	if err != nil {
		return gadb.DestV1{}, err
	}
	return cm.Dest, nil
}

func (s *Store) EnableByDest(ctx context.Context, dbtx gadb.DBTX, dest gadb.DestV1) error {
	err := permission.LimitCheckAny(ctx, permission.System)
	if err != nil {
		return err
	}

	id, err := gadb.New(dbtx).ContactMethodEnableDisable(ctx, gadb.ContactMethodEnableDisableParams{
		Dest:     gadb.NullDestV1{Valid: true, DestV1: dest},
		Disabled: false,
	})

	if err == nil {
		// NOTE: maintain a record of consent/dissent
		logCtx := log.WithFields(ctx, log.Fields{
			"contactMethodID": id,
		})

		log.Logf(logCtx, "Contact method START code received.")
	}

	return err
}

func (s *Store) DisableByDest(ctx context.Context, dbtx gadb.DBTX, dest gadb.DestV1) error {
	err := permission.LimitCheckAny(ctx, permission.System)
	if err != nil {
		return err
	}

	id, err := gadb.New(dbtx).ContactMethodEnableDisable(ctx, gadb.ContactMethodEnableDisableParams{
		Dest:     gadb.NullDestV1{Valid: true, DestV1: dest},
		Disabled: true,
	})

	if err == nil {
		// NOTE: maintain a record of consent/dissent
		logCtx := log.WithFields(ctx, log.Fields{
			"contactMethodID": id,
		})

		log.Logf(logCtx, "Contact method STOP code received.")
	}

	return err
}

// CreateTx inserts the new ContactMethod into the database. A new ID is always created.
func (s *Store) Create(ctx context.Context, dbtx gadb.DBTX, c *ContactMethod, scope ...*uuid.UUID) (*ContactMethod, error) {
	err := permission.LimitCheckAny(ctx, permission.System, permission.Admin, permission.MatchUser(c.UserID))
	if err != nil {
		return nil, err
	}

	if err := s.AuthorizeUser(ctx, dbtx, c.UserID, scope...); err != nil {
		return nil, err
	}
	n, err := c.Normalize(ctx, s.reg)
	if err != nil {
		return nil, err
	}

	err = gadb.New(dbtx).ContactMethodAdd(ctx, gadb.ContactMethodAddParams{
		ID:                  n.ID,
		Name:                n.Name,
		Dest:                gadb.NullDestV1{Valid: true, DestV1: n.Dest},
		Disabled:            n.Disabled,
		UserID:              uuid.MustParse(n.UserID),
		EnableStatusUpdates: n.StatusUpdates,
		Private:             n.Private,
	})
	if err != nil {
		return nil, err
	}

	return n.forViewer(ctx), nil
}

// Delete removes the ContactMethod from the database using the provided ID within a transaction.
func (s *Store) Delete(ctx context.Context, dbtx gadb.DBTX, ids ...string) error {
	err := permission.LimitCheckAny(ctx, permission.Admin, permission.User)
	if err != nil {
		return err
	}

	if len(ids) == 0 {
		return nil
	}

	uids, err := validate.ParseManyUUID("ContactMethodID", ids, 50)
	if err != nil {
		return err
	}

	if permission.Admin(ctx) {
		err = gadb.New(dbtx).DeleteContactMethod(ctx, uids)
		return err
	}

	rows, err := gadb.New(dbtx).ContactMethodLookupUserID(ctx, uids)
	if err != nil {
		return err
	}

	var checks []permission.Checker
	for _, id := range rows {
		checks = append(checks, permission.MatchUser(id.String()))
	}

	err = permission.LimitCheckAny(ctx, checks...)
	if err != nil {
		return err
	}

	err = gadb.New(dbtx).DeleteContactMethod(ctx, uids)
	return err
}

// FindOneTx finds the contact method from the database using the provided ID within a transaction.
func (s *Store) FindOne(ctx context.Context, dbtx gadb.DBTX, id uuid.UUID, scope ...*uuid.UUID) (*ContactMethod, error) {
	if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
		return nil, err
	}
	cms, err := s.read(ctx, dbtx, []uuid.UUID{id}, uuid.NullUUID{}, scope)
	if err != nil {
		return nil, err
	}
	if len(cms) == 0 {
		return nil, sql.ErrNoRows
	}
	return &cms[0], nil
}

// UpdateTx updates the contact method with the newly provided values within a transaction.
func (s *Store) Update(ctx context.Context, dbtx gadb.DBTX, c *ContactMethod, scope ...*uuid.UUID) error {
	err := permission.LimitCheckAny(ctx, permission.Admin, permission.User)
	if err != nil {
		return err
	}

	n, err := c.Normalize(ctx, s.reg)
	if err != nil {
		return err
	}

	cm, err := s.FindOneForUpdate(ctx, dbtx, c.ID, scope...)
	if err != nil {
		return err
	}
	if !n.Dest.Equal(cm.Dest) {
		return validation.NewFieldError("Dest", "cannot update destination of contact method")
	}
	if n.UserID != cm.UserID {
		return validation.NewFieldError("UserID", "cannot update owner of contact method")
	}

	if n.Private != cm.Private && !permission.System(ctx) && cm.UserID != permission.UserID(ctx) {
		return permission.NewAccessDenied("only the Contact Method owner can change privacy")
	}

	if permission.Admin(ctx) {
		err = gadb.New(dbtx).ContactMethodUpdate(ctx, gadb.ContactMethodUpdateParams{ID: n.ID, Name: n.Name, Disabled: n.Disabled, EnableStatusUpdates: n.StatusUpdates, Private: n.Private})
		return err
	}

	err = permission.LimitCheckAny(ctx, permission.MatchUser(cm.UserID))
	if err != nil {
		return err
	}

	err = gadb.New(dbtx).ContactMethodUpdate(ctx, gadb.ContactMethodUpdateParams{ID: n.ID, Name: n.Name, Disabled: n.Disabled, EnableStatusUpdates: n.StatusUpdates, Private: n.Private})

	return err
}

// FindMany will fetch all contact methods matching the given ids.
func (s *Store) FindMany(ctx context.Context, dbtx gadb.DBTX, ids []string, scope ...*uuid.UUID) ([]ContactMethod, error) {
	uids, err := validate.ParseManyUUID("ContactMethodID", ids, 50)
	if err != nil {
		return nil, err
	}
	if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
		return nil, err
	}
	return s.read(ctx, dbtx, uids, uuid.NullUUID{}, scope)
}

// FindAll returns authorized metadata with owner-only private arguments.
func (s *Store) FindAll(ctx context.Context, dbtx gadb.DBTX, userID string, scope ...*uuid.UUID) ([]ContactMethod, int, error) {
	uid, err := validate.ParseUUID("UserID", userID)
	if err != nil {
		return nil, 0, err
	}
	if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
		return nil, 0, err
	}
	cms, err := s.read(ctx, dbtx, nil, uuid.NullUUID{UUID: uid, Valid: true}, scope)
	return cms, 0, err
}
