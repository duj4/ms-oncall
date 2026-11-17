package scheduledataref

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/util/sqlutil"
)

// Lock validates exactly the final bytes that the caller will persist. The
// caller must already own the ScheduleData row (or its new INSERT) and must
// write these same bytes in this transaction. Locks live until transaction end.
//
// Existing processing/data locks precede parent -> sorted Users -> sorted
// assignments -> Organization -> NormalOrganization. All added row locks use
// NOWAIT; the deadline also bounds relation-lock waits. SHARE, rather than KEY
// SHARE, freezes non-key role/scope changes and conflicts with DELETE/UPDATE.
// RepeatableRead's 40001 is returned unchanged; no stale-payload retry occurs.
func Lock(ctx context.Context, tx *sql.Tx, scheduleID uuid.UUID, raw []byte, scope *uuid.UUID) error {
	users, err := Users(raw, scheduleID)
	if err != nil || tx == nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var org uuid.UUID
	if err := tx.QueryRowContext(ctx, `SELECT organization_id FROM public.schedules WHERE id=$1 FOR SHARE NOWAIT`, scheduleID).Scan(&org); err != nil {
		return err
	}
	if scope != nil && (*scope == uuid.Nil || *scope != org) {
		return ErrInvalid
	}
	ids := make([]string, len(users))
	for i, id := range users {
		ids[i] = id.String()
	}
	for _, query := range []string{
		`SELECT id FROM public.users WHERE id=ANY($1::uuid[]) ORDER BY id FOR SHARE NOWAIT`,
		`SELECT user_id FROM public.user_organization_assignments WHERE user_id=ANY($1::uuid[]) ORDER BY user_id FOR SHARE NOWAIT`,
	} {
		rows, err := tx.QueryContext(ctx, query, sqlutil.StringArray(ids))
		if err != nil {
			return err
		}
		i := 0
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			if i >= len(users) || id != users[i] {
				rows.Close()
				return ErrInvalid
			}
			i++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if i != len(users) {
			return ErrInvalid
		}
	}
	// No affiliation is needed for an envelope with no User references.
	if len(users) == 0 {
		return nil
	}
	for _, query := range []string{
		`SELECT id FROM public.organizations WHERE id=$1 FOR SHARE NOWAIT`,
		`SELECT organization_id FROM public.normal_organizations WHERE organization_id=$1 FOR SHARE NOWAIT`,
	} {
		var id uuid.UUID
		if err := tx.QueryRowContext(ctx, query, org).Scan(&id); err != nil {
			return err
		}
		if id != org {
			return ErrInvalid
		}
	}
	// Re-evaluate the existing operational affiliation relation only after its
	// inputs are locked. It includes User role, assignment truth and Normal scope.
	var count int
	err = tx.QueryRowContext(ctx, `SELECT count(*) FROM (`+organization.CurrentUserOrganizationsQuery+`) affiliation WHERE id=ANY($1::uuid[]) AND effective_organization_id=$2`, sqlutil.StringArray(ids), org).Scan(&count)
	if err != nil {
		return err
	}
	if count != len(users) {
		return ErrInvalid
	}
	return nil
}
