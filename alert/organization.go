package alert

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation"
)

func checkOrganizationID(organizationID *uuid.UUID) error {
	if organizationID != nil && *organizationID == uuid.Nil {
		return validation.NewFieldError("OrganizationID", "must be specified")
	}
	return nil
}

// CheckOrganization authorizes current Alert access through its owning Service.
// Nil preserves the existing non-human path without an additional query. This
// is a non-locking check; it does not attribute historical events to an Organization.
func (s *Store) CheckOrganization(ctx context.Context, db gadb.DBTX, id int, organizationID *uuid.UUID) error {
	if organizationID == nil {
		return nil
	}
	if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
		return err
	}
	if err := checkOrganizationID(organizationID); err != nil {
		return err
	}
	_, err := gadb.New(db).Alert_CheckOrganization(ctx, gadb.Alert_CheckOrganizationParams{
		ID: int64(id), OrganizationID: *organizationID,
	})
	return err
}

func (s *Store) checkServiceOrganization(ctx context.Context, db gadb.DBTX, serviceID string, organizationID *uuid.UUID) error {
	if organizationID == nil {
		return nil
	}
	if err := checkOrganizationID(organizationID); err != nil {
		return err
	}
	_, err := gadb.New(db).Alert_CheckServiceOrganization(ctx, gadb.Alert_CheckServiceOrganizationParams{
		ID: uuid.MustParse(serviceID), OrganizationID: *organizationID,
	})
	if err == sql.ErrNoRows {
		return validation.NewFieldError("ServiceID", "service does not exist")
	}
	return err
}

// organizationAlertIDs hides foreign IDs like missing IDs. Status updates have
// always updated the existing subset in one transaction. Feedback instead uses
// requireAll because its existing INSERT is all-or-nothing, including missing IDs.
func (s *Store) organizationAlertIDs(ctx context.Context, db gadb.DBTX, ids []int, organizationID *uuid.UUID, requireAll bool) ([]int, error) {
	if organizationID == nil {
		return ids, nil
	}
	if err := checkOrganizationID(organizationID); err != nil {
		return nil, err
	}
	want := make(map[int]bool, len(ids))
	values := make([]int64, len(ids))
	for i, id := range ids {
		want[id] = true
		values[i] = int64(id)
	}
	rows, err := gadb.New(db).Alert_OrganizationIDs(ctx, gadb.Alert_OrganizationIDsParams{
		Ids: values, OrganizationID: *organizationID,
	})
	if err != nil {
		return nil, err
	}
	if requireAll && len(rows) != len(want) {
		return nil, sql.ErrNoRows
	}
	if requireAll {
		return ids, nil // Preserve duplicate-input validation by the original SQL.
	}
	result := make([]int, len(rows))
	for i, id := range rows {
		result[i] = int(id)
	}
	return result, nil
}
