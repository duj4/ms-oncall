package integrationkey

import (
	"context"
	"database/sql"

	"github.com/target/goalert/auth/authtoken"
	"github.com/target/goalert/expflag"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/keyring"
	"github.com/target/goalert/notification/nfydest"
	"github.com/target/goalert/notificationchannel"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation"
	"github.com/target/goalert/validation/validate"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type Store struct {
	db *sql.DB

	keys    keyring.Keyring
	reg     *nfydest.Registry
	ncStore *notificationchannel.Store
}

func NewStore(ctx context.Context, db *sql.DB, keys keyring.Keyring, reg *nfydest.Registry, ncStore *notificationchannel.Store) *Store {
	return &Store{db: db, keys: keys, reg: reg, ncStore: ncStore}
}

func (s *Store) Authorize(ctx context.Context, tok authtoken.Token, t Type) (context.Context, error) {
	var serviceID string
	var err error
	permission.SudoContext(ctx, func(c context.Context) {
		serviceID, err = s.GetServiceID(c, tok.ID.String(), t)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ctx, permission.Unauthorized()
	}
	if err != nil {
		return ctx, errors.Wrap(err, "lookup serviceID")
	}
	ctx = permission.ServiceSourceContext(ctx, serviceID, &permission.SourceInfo{
		Type: permission.SourceTypeIntegrationKey,
		ID:   tok.ID.String(),
	})
	return ctx, nil
}

func (s *Store) GetServiceID(ctx context.Context, id string, t Type) (string, error) {
	keyUUID, err := validate.ParseUUID("IntegrationKeyID", id)
	err = validate.Many(
		err,
		validate.OneOf("IntegrationType", t, TypeGrafana, TypeSite24x7, TypePrometheusAlertmanager, TypeGeneric, TypeEmail, TypeUniversal),
	)
	if err != nil {
		return "", err
	}
	err = permission.LimitCheckAny(ctx, permission.System, permission.Admin, permission.User)
	if err != nil {
		return "", err
	}

	serviceID, err := gadb.New(s.db).IntKeyGetServiceID(ctx, gadb.IntKeyGetServiceIDParams{
		ID:   keyUUID,
		Type: gadb.EnumIntegrationKeysType(t),
	})

	if errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if err != nil {
		return "", errors.WithMessage(err, "lookup failure")
	}

	return serviceID.String(), nil
}

func (s *Store) Create(ctx context.Context, dbtx gadb.DBTX, i *IntegrationKey, organizationID *uuid.UUID) (*IntegrationKey, error) {
	err := permission.LimitCheckAny(ctx, permission.Admin, permission.User)
	if err != nil {
		return nil, err
	}

	n, err := i.Normalize()
	if err != nil {
		return nil, err
	}

	if i.Type == TypeUniversal && !expflag.ContextHas(ctx, expflag.UnivKeys) {
		return nil, validation.NewGenericError("experimental flag not enabled")
	}

	serviceUUID, err := uuid.Parse(n.ServiceID)
	if err != nil {
		return nil, err
	}

	// Preserve local validation precedence; ownership is checked only when the
	// owning Service is needed for persistence, in the caller's transaction.
	if organizationID != nil {
		if *organizationID == uuid.Nil {
			return nil, validation.NewFieldError("OrganizationID", "must be specified")
		}
		_, err = gadb.New(dbtx).IntKeyCheckServiceOrganization(ctx, gadb.IntKeyCheckServiceOrganizationParams{
			ServiceID: serviceUUID, OrganizationID: *organizationID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil, validation.NewFieldError("ServiceID", "does not exist")
		}
		if err != nil {
			return nil, err
		}
	}

	keyUUID := uuid.New()
	n.ID = keyUUID.String()
	err = gadb.New(dbtx).IntKeyCreate(ctx, gadb.IntKeyCreateParams{
		ID:        keyUUID,
		Name:      n.Name,
		Type:      gadb.EnumIntegrationKeysType(n.Type),
		ServiceID: serviceUUID,

		ExternalSystemName: sql.NullString{String: n.ExternalSystemName, Valid: n.ExternalSystemName != ""},
	})
	if err != nil {
		return nil, err
	}

	if n.Type == TypeUniversal {
		// ensure a config exists
		err = s.SetConfig(ctx, dbtx, keyUUID, &gadb.UIKConfigV1{})
		if err != nil {
			return nil, err
		}
	}

	return n, nil
}

func (s *Store) Delete(ctx context.Context, dbtx gadb.DBTX, id string, organizationID *uuid.UUID) error {
	return s.DeleteMany(ctx, dbtx, []string{id}, organizationID)
}

func (s *Store) DeleteMany(ctx context.Context, dbtx gadb.DBTX, ids []string, organizationID *uuid.UUID) error {
	err := permission.LimitCheckAny(ctx, permission.Admin, permission.User)
	if err != nil {
		return err
	}

	uuids, err := validate.ParseManyUUID("IntegrationKeyID", ids, 50)
	if err != nil {
		return err
	}

	if organizationID == nil {
		return gadb.New(dbtx).IntKeyDelete(ctx, uuids)
	}
	if *organizationID == uuid.Nil {
		return validation.NewFieldError("OrganizationID", "must be specified")
	}
	want := make(map[uuid.UUID]struct{}, len(uuids))
	for _, id := range uuids {
		want[id] = struct{}{}
	}
	// The count predicate prevents partial deletion even without a caller Tx.
	// DeleteAll also rolls back earlier target groups on a mismatch.
	rows, err := gadb.New(dbtx).IntKeyDeleteOrganization(ctx, gadb.IntKeyDeleteOrganizationParams{
		Ids: uuids, OrganizationID: *organizationID,
	})
	if err != nil {
		return err
	}
	if rows != int64(len(want)) {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) FindOne(ctx context.Context, id string, organizationID *uuid.UUID) (*IntegrationKey, error) {
	keyUUID, err := validate.ParseUUID("IntegrationKeyID", id)
	if err != nil {
		return nil, err
	}

	err = permission.LimitCheckAny(ctx, permission.Admin, permission.User)
	if err != nil {
		return nil, err
	}

	scope, err := organizationScope(organizationID)
	if err != nil {
		return nil, err
	}
	row, err := gadb.New(s.db).IntKeyFindOne(ctx, gadb.IntKeyFindOneParams{ID: keyUUID, OrganizationID: scope})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &IntegrationKey{
		ID:        row.ID.String(),
		Name:      row.Name,
		Type:      Type(row.Type),
		ServiceID: row.ServiceID.String(),

		ExternalSystemName: row.ExternalSystemName.String,
	}, nil
}

func (s *Store) FindAllByService(ctx context.Context, serviceID string, organizationID *uuid.UUID) ([]IntegrationKey, error) {
	serviceUUID, err := validate.ParseUUID("ServiceID", serviceID)
	if err != nil {
		return nil, err
	}

	err = permission.LimitCheckAny(ctx, permission.Admin, permission.User)
	if err != nil {
		return nil, err
	}

	scope, err := organizationScope(organizationID)
	if err != nil {
		return nil, err
	}
	rows, err := gadb.New(s.db).IntKeyFindByService(ctx, gadb.IntKeyFindByServiceParams{ServiceID: serviceUUID, OrganizationID: scope})
	if err != nil {
		return nil, err
	}
	keys := make([]IntegrationKey, len(rows))
	for i, row := range rows {
		keys[i] = IntegrationKey{
			ID:        row.ID.String(),
			Name:      row.Name,
			Type:      Type(row.Type),
			ServiceID: row.ServiceID.String(),

			ExternalSystemName: row.ExternalSystemName.String,
		}
	}
	return keys, nil
}

// CheckOrganization authorizes a key through its immutable owning Service before
// an application boundary reads or mutates sensitive token/configuration state.
// Nil preserves the bounded non-human compatibility path without additional SQL.
func (s *Store) CheckOrganization(ctx context.Context, dbtx gadb.DBTX, id uuid.UUID, organizationID *uuid.UUID) error {
	if organizationID == nil {
		return nil
	}
	if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
		return err
	}
	if *organizationID == uuid.Nil {
		return validation.NewFieldError("OrganizationID", "must be specified")
	}
	_, err := gadb.New(dbtx).IntKeyCheckOrganization(ctx, gadb.IntKeyCheckOrganizationParams{
		ID: id, OrganizationID: *organizationID,
	})
	return err
}

func organizationScope(id *uuid.UUID) (uuid.NullUUID, error) {
	if id == nil {
		return uuid.NullUUID{}, nil
	}
	if *id == uuid.Nil {
		return uuid.NullUUID{}, validation.NewFieldError("OrganizationID", "must be specified")
	}
	return uuid.NullUUID{UUID: *id, Valid: true}, nil
}
