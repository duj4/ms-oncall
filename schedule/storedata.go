package schedule

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/internal/scheduledataref"
	"github.com/target/goalert/util/jsonutil"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation"
)

func (store *Store) scheduleData(ctx context.Context, tx *sql.Tx, scheduleID uuid.UUID) (*Data, error) {
	db := gadb.New(store.db)
	if tx != nil {
		db = db.WithTx(tx)
	}
	rawData, err := db.SchedFindData(ctx, scheduleID)
	if err == sql.ErrNoRows {
		err = nil
	}
	if err != nil {
		return nil, err
	}

	var data Data
	if len(rawData) > 0 {
		err = json.Unmarshal(rawData, &data)
		if err != nil {
			return nil, err
		}
	}

	return &data, nil
}

func (store *Store) updateScheduleData(ctx context.Context, tx *sql.Tx, scheduleID uuid.UUID, organizationID *uuid.UUID, apply func(*sql.Tx, *Data) error, finish ...func(*sql.Tx, *Data) error) (retErr error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var err error
	externalTx := tx != nil
	if !externalTx {
		tx, err = store.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer sqlutil.Rollback(ctx, "schedule: update data", tx)
	}
	// A rejected final envelope must not leave even the initial empty INSERT in
	// a caller-owned transaction that elects to continue after this error.
	if externalTx {
		if _, err := tx.ExecContext(ctx, `SAVEPOINT schedule_data_writer`); err != nil {
			return err
		}
		defer func() {
			end, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer cancel()
			if retErr != nil {
				_, err := tx.ExecContext(end, `ROLLBACK TO SAVEPOINT schedule_data_writer`)
				retErr = errors.Join(retErr, err)
			}
			_, err := tx.ExecContext(end, `RELEASE SAVEPOINT schedule_data_writer`)
			retErr = errors.Join(retErr, err)
		}()
	}

	db := gadb.New(store.db).WithTx(tx)
	if organizationID != nil {
		if *organizationID == uuid.Nil {
			return validation.NewFieldError("OrganizationID", "must be specified")
		}
		// Authorize the parent in the persistence transaction before reading or
		// locking any Schedule-owned data. This check does not lock the parent.
		_, err = db.SchedCheckOrganization(ctx, gadb.SchedCheckOrganizationParams{
			ScheduleID:     scheduleID,
			OrganizationID: *organizationID,
		})
		if err == sql.ErrNoRows {
			return validation.NewFieldError("ScheduleID", "schedule does not exist")
		}
		if err != nil {
			return err
		}
	}

	var rawData json.RawMessage
	// ON CONFLICT keeps a raced INSERT from aborting the PostgreSQL transaction.
	// Always re-read and lock the winner's complete envelope before applying.
	rawData, err = db.SchedFindDataForUpdate(ctx, scheduleID)
	if err == sql.ErrNoRows {
		err = db.SchedInsertData(ctx, scheduleID)
		if err == nil {
			rawData, err = db.SchedFindDataForUpdate(ctx, scheduleID)
		}
	}
	if err != nil {
		return err
	}

	var data Data
	if len(rawData) > 0 {
		// '{}' is the SQL initializer, never the final persisted output. Validate
		// other inputs before a typed array rewrite can erase unknown fields.
		if strings.TrimSpace(string(rawData)) != "{}" {
			if _, err := scheduledataref.Users(rawData, scheduleID); err != nil {
				return err
			}
		}
		err = json.Unmarshal(rawData, &data)
		if err != nil {
			return err
		}
	}

	err = apply(tx, &data)
	if err != nil {
		return err
	}

	// preserve unknown fields
	rawData, err = jsonutil.Apply(rawData, data)
	if err != nil {
		return err
	}

	if err := scheduledataref.Lock(ctx, tx, scheduleID, rawData, organizationID); err != nil {
		return err
	}
	err = db.SchedUpdateData(ctx, gadb.SchedUpdateDataParams{
		ScheduleID: scheduleID,
		Data:       rawData,
	})
	if err != nil {
		return err
	}

	if len(finish) > 0 {
		var matches bool
		if err := tx.QueryRowContext(ctx, `SELECT data=$2::jsonb FROM schedule_data WHERE schedule_id=$1`, scheduleID, rawData).Scan(&matches); err != nil {
			return err
		}
		if !matches {
			return scheduledataref.ErrInvalid
		}
	}

	for _, fn := range finish {
		if err := fn(tx, &data); err != nil {
			return err
		}
	}

	if !externalTx {
		return tx.Commit()
	}

	return nil
}
