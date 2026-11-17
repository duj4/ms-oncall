package escalation

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/internal/updateguard"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/schedule/rotation"
	"github.com/target/goalert/user"
	"github.com/target/goalert/validation"
	"github.com/target/goalert/validation/validate"
)

func (s *Store) AddStepActionTx(ctx context.Context, tx *sql.Tx, stepID uuid.UUID, dest gadb.DestV1) error {
	err := permission.LimitCheckAny(ctx, permission.User)
	if err != nil {
		return err
	}

	typeInfo, err := s.reg.TypeInfo(ctx, dest.Type)
	if err != nil {
		return err
	}
	if !typeInfo.IsEPTarget() {
		return validation.NewGenericError("not a valid escalation policy destination")
	}

	var userID, scheduleID, rotationID, channelID uuid.NullUUID
	switch dest.Type {
	case user.DestTypeUser:
		id, err := validate.ParseUUID("ID", dest.Arg(user.FieldUserID))
		if err != nil {
			return err
		}
		userID = uuid.NullUUID{UUID: id, Valid: true}
	case schedule.DestTypeSchedule:
		id, err := validate.ParseUUID("ID", dest.Arg(schedule.FieldScheduleID))
		if err != nil {
			return err
		}
		scheduleID = uuid.NullUUID{UUID: id, Valid: true}
	case rotation.DestTypeRotation:
		id, err := validate.ParseUUID("ID", dest.Arg(rotation.FieldRotationID))
		if err != nil {
			return err
		}
		rotationID = uuid.NullUUID{UUID: id, Valid: true}
	default:
		id, err := s.ncStore.MapDestToID(ctx, tx, dest)
		if err != nil {
			return err
		}
		channelID = uuid.NullUUID{UUID: id, Valid: true}
	}

	return gadb.New(tx).EPStepActionsAddAction(ctx, gadb.EPStepActionsAddActionParams{
		EscalationPolicyStepID: stepID,
		UserID:                 userID,
		ScheduleID:             scheduleID,
		RotationID:             rotationID,
		ChannelID:              channelID,
	})
}

func (s *Store) DeleteStepActionTx(ctx context.Context, tx *sql.Tx, stepID uuid.UUID, dest gadb.DestV1) error {
	_, err := s.DeleteStepActionReceiptTx(ctx, tx, stepID, dest)
	return err
}

// DeleteStepActionReceiptTx uses the same destination matching and validation as
// DeleteStepActionTx. Only DELETE RETURNING supplies deleted database identities;
// destinations and channel payloads never enter the receipt projection.
func (s *Store) DeleteStepActionReceiptTx(ctx context.Context, tx *sql.Tx, stepID uuid.UUID, dest gadb.DestV1) ([]gadb.EPStepActionsDeleteReceiptRow, error) {
	params, err := s.stepActionDeleteParams(ctx, tx, stepID, dest)
	if err != nil {
		return nil, err
	}
	if err := updateguard.Require(ctx, tx); err != nil {
		return nil, err
	}
	rows, err := gadb.New(tx).EPStepActionsDeleteReceipt(ctx, gadb.EPStepActionsDeleteReceiptParams(params))
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if err := updateguard.Consume(ctx, tx, ds.Resource{Kind: ds.ResourceEscalationPolicyAction, ID: r.ID.String()}); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

// StepActionDeleteIDsTx resolves the existing deletion predicate without DML.
// Preview and Update use the same destination equality and persisted identities.
func (s *Store) StepActionDeleteIDsTx(ctx context.Context, tx *sql.Tx, stepID uuid.UUID, dest gadb.DestV1) ([]uuid.UUID, error) {
	p, err := s.stepActionDeleteParams(ctx, tx, stepID, dest)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM escalation_policy_actions WHERE escalation_policy_step_id=$1 AND (user_id=$2 OR schedule_id=$3 OR rotation_id=$4 OR channel_id=$5) ORDER BY id`, p.EscalationPolicyStepID, p.UserID, p.ScheduleID, p.RotationID, p.ChannelID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) stepActionDeleteParams(ctx context.Context, tx *sql.Tx, stepID uuid.UUID, dest gadb.DestV1) (gadb.EPStepActionsDeleteActionParams, error) {
	err := permission.LimitCheckAny(ctx, permission.User)
	if err != nil {
		return gadb.EPStepActionsDeleteActionParams{}, err
	}

	var userID, scheduleID, rotationID, channelID uuid.NullUUID
	switch dest.Type {
	case user.DestTypeUser:
		id, err := validate.ParseUUID("ID", dest.Arg(user.FieldUserID))
		if err != nil {
			return gadb.EPStepActionsDeleteActionParams{}, err
		}
		userID = uuid.NullUUID{UUID: id, Valid: true}
	case schedule.DestTypeSchedule:
		id, err := validate.ParseUUID("ID", dest.Arg(schedule.FieldScheduleID))
		if err != nil {
			return gadb.EPStepActionsDeleteActionParams{}, err
		}
		scheduleID = uuid.NullUUID{UUID: id, Valid: true}
	case rotation.DestTypeRotation:
		id, err := validate.ParseUUID("ID", dest.Arg(rotation.FieldRotationID))
		if err != nil {
			return gadb.EPStepActionsDeleteActionParams{}, err
		}
		rotationID = uuid.NullUUID{UUID: id, Valid: true}
	default:
		if s.ncStore == nil {
			return gadb.EPStepActionsDeleteActionParams{}, &ds.DeletionSafetyError{Code: ds.DeletionUnavailable}
		}
		id, err := s.ncStore.LookupDestID(ctx, tx, dest)
		if err != nil {
			return gadb.EPStepActionsDeleteActionParams{}, err
		}
		channelID = uuid.NullUUID{UUID: id, Valid: true}
	}

	return gadb.EPStepActionsDeleteActionParams{
		EscalationPolicyStepID: stepID,
		UserID:                 userID,
		ScheduleID:             scheduleID,
		RotationID:             rotationID,
		ChannelID:              channelID,
	}, nil
}

func (s *Store) FindAllStepActionsTx(ctx context.Context, tx gadb.DBTX, stepID uuid.UUID) ([]gadb.DestV1, error) {
	err := permission.LimitCheckAny(ctx, permission.User)
	if err != nil {
		return nil, err
	}

	if tx == nil {
		tx = s.db
	}

	actions, err := gadb.New(tx).EPStepActionsByStepId(ctx, stepID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	result := make([]gadb.DestV1, 0, len(actions))
	for _, a := range actions {
		switch {
		case a.UserID.Valid:
			result = append(result, user.DestFromID(a.UserID.UUID.String()))
		case a.ScheduleID.Valid:
			result = append(result, schedule.DestFromID(a.ScheduleID.UUID.String()))
		case a.RotationID.Valid:
			result = append(result, rotation.DestFromID(a.RotationID.UUID.String()))
		case a.Dest.Valid:
			result = append(result, a.Dest.DestV1)
		}
	}

	return result, nil
}
