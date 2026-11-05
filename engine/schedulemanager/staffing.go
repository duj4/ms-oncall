package schedulemanager

import (
	"context"
	"database/sql"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/uuid"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/util/sqlutil"
)

// Read both persisted parents and current affiliations in the existing
// RepeatableRead transaction. A failed read aborts the whole update, rather
// than interpreting unavailable authority as an empty eligible set. Two batch
// queries avoid a per-user lookup and acquire no additional row locks.
func loadStaffingEligibility(ctx context.Context, tx *sql.Tx, data map[uuid.UUID]*updateInfo, now time.Time) error {
	users := mapset.NewThreadUnsafeSet[uuid.UUID]()
	for _, info := range data {
		users = users.Union(info.calcLatestOnCall(now))
		info.EligibleUsers = mapset.NewThreadUnsafeSet[uuid.UUID]()
	}
	affiliation := make(map[uuid.UUID]uuid.UUID)
	userIDs := make([]string, 0, users.Cardinality())
	for userID := range mapset.Elements(users) {
		userIDs = append(userIDs, userID.String())
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, effective_organization_id FROM (`+
		organization.CurrentUserOrganizationsQuery+`) affiliation WHERE id = ANY($1::uuid[])`, sqlutil.UUIDArray(userIDs))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var userID, orgID uuid.UUID
		if err := rows.Scan(&userID, &orgID); err != nil {
			return err
		}
		affiliation[userID] = orgID
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, `SELECT id, organization_id FROM schedules`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var scheduleID, orgID uuid.UUID
		if err := rows.Scan(&scheduleID, &orgID); err != nil {
			return err
		}
		if info := data[scheduleID]; info != nil {
			for userID := range mapset.Elements(info.calcLatestOnCall(now)) {
				if affiliation[userID] == orgID && orgID != uuid.Nil {
					info.EligibleUsers.Add(userID)
				}
			}
		}
	}
	return rows.Err()
}
