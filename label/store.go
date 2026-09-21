package label

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation"
	"github.com/target/goalert/validation/validate"

	"github.com/pkg/errors"
)

// Store allows the lookup and management of Labels.
type Store struct {
	db *sql.DB
}

// NewStore will Set a DB backend from a sql.DB. An error will be returned if statements fail to prepare.
func NewStore(ctx context.Context, db *sql.DB) (*Store, error) { return &Store{db: db}, nil }

// SetTx will set a label for the service. It can be used to set the key-value pair for the label,
// delete a label or update the value given the label's key.
// Organization authority is supplied by the application boundary; nil retains
// the authorized internal/non-human compatibility path. The caller owns tx.
func (s *Store) SetTx(ctx context.Context, tx *sql.Tx, label *Label, organizationID *uuid.UUID) error {
	err := permission.LimitCheckAny(ctx, permission.System, permission.User)
	if err != nil {
		return err
	}

	n, err := label.Normalize()
	if err != nil {
		return err
	}

	scope, err := organizationScope(organizationID)
	if err != nil {
		return err
	}
	if scope.Valid {
		// Authorize the immutable parent ownership in this transaction before
		// reading or waiting on any Label mutation row. No parent lock is needed.
		allowed, err := gadb.New(tx).LabelCheckServiceOrganization(ctx, gadb.LabelCheckServiceOrganizationParams{
			ID: uuid.MustParse(n.Target.TargetID()), OrganizationID: scope.UUID,
		})
		if errors.Is(err, sql.ErrNoRows) && n.Value == "" {
			return nil // Preserve deletion of a missing Service's label as a no-op.
		}
		if err != nil {
			return err
		}
		if !allowed {
			return sql.ErrNoRows
		}
	}

	if n.Value == "" { // delete if value is empty
		err = gadb.New(tx).LabelDeleteKeyByTarget(ctx, gadb.LabelDeleteKeyByTargetParams{
			Key:          label.Key,
			TgtServiceID: uuid.MustParse(label.Target.TargetID()),
		})
		if err != nil {
			return fmt.Errorf("delete label: %w", err)
		}

		return nil
	}

	err = gadb.New(tx).LabelSetByTarget(ctx, gadb.LabelSetByTargetParams{
		Key:          label.Key,
		Value:        label.Value,
		TgtServiceID: uuid.MustParse(label.Target.TargetID()),
	})
	if err != nil {
		return fmt.Errorf("set label: %w", err)
	}

	return nil
}

// FindAllByService finds all labels for a particular service. It returns all key-value pairs.
func (s *Store) FindAllByService(ctx context.Context, db gadb.DBTX, serviceID string, organizationID *uuid.UUID) ([]Label, error) {
	err := permission.LimitCheckAny(ctx, permission.System, permission.User)
	if err != nil {
		return nil, err
	}

	svc, err := validate.ParseUUID("ServiceID", serviceID)
	if err != nil {
		return nil, err
	}

	scope, err := organizationScope(organizationID)
	if err != nil {
		return nil, err
	}
	rows, err := gadb.New(db).LabelFindAllByTarget(ctx, gadb.LabelFindAllByTargetParams{
		TgtServiceID: svc, OrganizationID: scope,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find all labels by service: %w", err)
	}

	labels := make([]Label, len(rows))
	for i, l := range rows {
		labels[i].Key = l.Key
		labels[i].Value = l.Value
		labels[i].Target = assignment.ServiceTarget(serviceID)
	}

	return labels, nil
}

func (s *Store) UniqueKeysTx(ctx context.Context, db gadb.DBTX, organizationID *uuid.UUID) ([]string, error) {
	err := permission.LimitCheckAny(ctx, permission.System, permission.User)
	if err != nil {
		return nil, err
	}

	scope, err := organizationScope(organizationID)
	if err != nil {
		return nil, err
	}
	return gadb.New(db).LabelUniqueKeys(ctx, scope)
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
