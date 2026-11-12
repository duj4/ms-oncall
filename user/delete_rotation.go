package user

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	audit "github.com/target/goalert/user/deleteaudit"
)

func (c *userDeleteCapture) removeRotations() error {
	last := "00000000-0000-0000-0000-000000000000"
	for {
		var rotation uuid.UUID
		err := c.tx.QueryRowContext(c.ctx, `SELECT rotation_id FROM rotation_participants WHERE user_id=$1 AND rotation_id>$2::uuid GROUP BY rotation_id ORDER BY rotation_id LIMIT 1`, c.user, last).Scan(&rotation)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if err = c.removeRotation(rotation); err != nil {
			return err
		}
		last = rotation.String()
	}
}

func (c *userDeleteCapture) removeRotation(rotation uuid.UUID) error {
	var org uuid.UUID
	var originalCount int64
	err := c.tx.QueryRowContext(c.ctx, `SELECT organization_id,participant_count FROM rotations WHERE id=$1 FOR UPDATE`, rotation).Scan(&org, &originalCount)
	if err != nil {
		return err
	}
	resolution := "known_normal"
	if org.String() == "296e2656-7221-53fe-bd0a-832d24ccfd03" {
		resolution = "known_default"
	}

	var captured int64
	var cursor *int
	for {
		if err = c.budget.Reserve(4*audit.PageSize, 2*audit.PageSize*audit.MaxLeafBytes); err != nil {
			return err
		}
		rows, queryErr := c.tx.QueryContext(c.ctx, `WITH page AS MATERIALIZED (
   SELECT p.id,p.rotation_id,p.user_id,p.position,p.xmin::text::bigint AS row_version FROM rotation_participants p
   WHERE p.rotation_id=$2 AND ($5::integer IS NULL OR p.position>$5) ORDER BY p.position LIMIT 256
  ), numbered AS (SELECT page.*,row_number() OVER(ORDER BY position)-1+$6::bigint AS ordinal FROM page)
  INSERT INTO pg_temp.sd8_user_delete_witness(root_ordinal,resource_type,resource_key,original_ordinal,before_value,organization_id,org_resolution,emit)
  SELECT $1,'rotation_participant',id::text,ordinal,jsonb_build_object('id',id,'rotation_id',rotation_id,'user_id',user_id,'position',position,'ordinal',ordinal,'row_version',row_version),$3,$4,false FROM numbered ORDER BY ordinal
  RETURNING (before_value->>'position')::integer`, c.ordinal, rotation, org, resolution, cursor, captured)
		if queryErr != nil {
			return queryErr
		}
		n := int64(0)
		lastPosition := 0
		for rows.Next() {
			var position int
			if err = rows.Scan(&position); err != nil {
				break
			}
			if n == 0 || position > lastPosition {
				lastPosition = position
			}
			n++
		}
		if err == nil {
			err = rows.Err()
		}
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		if err = c.budget.Release(4*audit.PageSize, 2*audit.PageSize*audit.MaxLeafBytes); err != nil {
			return err
		}
		if n == 0 {
			break
		}
		if n > audit.PageSize || captured > int64(^uint64(0)>>1)-n {
			return audit.ErrInvalid
		}
		captured += n
		cursor = &lastPosition
	}

	var inventoryCount int64
	err = c.tx.QueryRowContext(c.ctx, `SELECT count(*) FROM pg_temp.sd8_user_delete_witness WHERE root_ordinal=$1 AND resource_type='rotation_participant' AND before_value->>'rotation_id'=$2`, c.ordinal, rotation.String()).Scan(&inventoryCount)
	if err != nil {
		return err
	}
	if inventoryCount == 0 || originalCount != inventoryCount || captured != inventoryCount {
		return fmt.Errorf("rotation witness check 1: %w", audit.ErrInvalid)
	}
	_, err = c.tx.ExecContext(c.ctx, `INSERT INTO pg_temp.sd8_user_delete_witness(root_ordinal,resource_type,resource_key,before_value,organization_id,org_resolution,emit)
 VALUES($1,'rotation_participant_count',$2::uuid::text,jsonb_build_object('rotation_id',$2::uuid,'participant_count',$3::bigint),$4,$5,false)`, c.ordinal, rotation.String(), originalCount, org, resolution)
	if err != nil {
		return err
	}
	stateFields := map[string]string{"id": "b.id", "rotation_id": "b.rotation_id", "participant_id": "b.rotation_participant_id", "position": "b.position", "shift_start": safeTimestampSQL("b.shift_start"), "version": "b.version"}
	var stateID int64
	var activeIndex int64
	var stateBefore []byte
	err = c.tx.QueryRowContext(c.ctx, `SELECT b.id,b.position,`+projectionSQL(stateFields)+` FROM rotation_state b WHERE b.rotation_id=$1`, rotation).Scan(&stateID, &activeIndex, &stateBefore)
	// Preserve the legacy missing-state failure before mutating Participants.
	if err != nil {
		return err
	}
	if err = audit.ValidateSnapshot("rotation_state", strconv.FormatInt(stateID, 10), stateBefore); err != nil {
		return err
	}
	_, err = c.tx.ExecContext(c.ctx, `INSERT INTO pg_temp.sd8_user_delete_witness(root_ordinal,resource_type,resource_key,before_value,organization_id,org_resolution,emit) VALUES($1,'rotation_state',$2,$3::jsonb,$4,$5,false)`, c.ordinal, strconv.FormatInt(stateID, 10), string(stateBefore), org, resolution)
	if err != nil {
		return err
	}
	type part struct {
		ordinal  int64
		id, user uuid.UUID
		position int
	}
	skipped := false
	curIndex := int64(-1)
	lastOrdinal := int64(-1)
	for {
		if err = c.budget.Reserve(4*audit.PageSize, 2*audit.PageSize*audit.MaxLeafBytes); err != nil {
			return err
		}
		rows, err := c.tx.QueryContext(c.ctx, `SELECT original_ordinal,resource_key::uuid,(before_value->>'user_id')::uuid,(before_value->>'position')::integer FROM pg_temp.sd8_user_delete_witness WHERE root_ordinal=$1 AND resource_type='rotation_participant' AND before_value->>'rotation_id'=$2 AND original_ordinal>$3 ORDER BY original_ordinal LIMIT 256`, c.ordinal, rotation.String(), lastOrdinal)
		if err != nil {
			return err
		}
		page := make([]part, 0, audit.PageSize)
		for rows.Next() {
			var p part
			if err = rows.Scan(&p.ordinal, &p.id, &p.user, &p.position); err != nil {
				break
			}
			page = append(page, p)
		}
		if err == nil {
			err = rows.Err()
		}
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		for _, p := range page {
			if p.ordinal != lastOrdinal+1 {
				return fmt.Errorf("rotation witness check 2: %w", audit.ErrInvalid)
			}
			lastOrdinal = p.ordinal
			if p.user == c.user {
				if p.ordinal < activeIndex {
					activeIndex--
				}
				skipped = true
				continue
			}
			curIndex++
			if !skipped {
				continue
			}
			var target uuid.UUID
			var expectedPosition int
			var oldUser uuid.UUID
			err = c.tx.QueryRowContext(c.ctx, `SELECT resource_key::uuid,(before_value->>'position')::integer,(before_value->>'user_id')::uuid FROM pg_temp.sd8_user_delete_witness WHERE root_ordinal=$1 AND resource_type='rotation_participant' AND before_value->>'rotation_id'=$2 AND original_ordinal=$3`, c.ordinal, rotation.String(), curIndex).Scan(&target, &expectedPosition, &oldUser)
			if err != nil {
				return err
			}
			var actualID, actualRotation, actualUser uuid.UUID
			var position int
			var version uint32
			err = c.tx.QueryRowContext(c.ctx, `UPDATE rotation_participants SET user_id=$2 WHERE id=$1 RETURNING id,rotation_id,user_id,position,xmin::text::bigint`, target, p.user).Scan(&actualID, &actualRotation, &actualUser, &position, &version)
			if err != nil {
				return err
			}
			if actualID != target || actualRotation != rotation || actualUser != p.user || position != expectedPosition || version == 0 {
				return fmt.Errorf("rotation witness check 3: %w", audit.ErrInvalid)
			}
			_, err = c.tx.ExecContext(c.ctx, `UPDATE pg_temp.sd8_user_delete_witness SET after_value=jsonb_build_object('id',$3::uuid,'rotation_id',$4::uuid,'user_id',$5::uuid,'position',$6::integer,'ordinal',$7::bigint,'row_version',$8::bigint),emit=$9 WHERE root_ordinal=$1 AND resource_type='rotation_participant' AND resource_key=$2`, c.ordinal, target.String(), target, rotation, p.user, position, curIndex, version, oldUser != p.user)
			if err != nil {
				return err
			}
		}
		if err = c.budget.Release(4*audit.PageSize, 2*audit.PageSize*audit.MaxLeafBytes); err != nil {
			return err
		}
		if len(page) == 0 {
			break
		}
	}
	if lastOrdinal+1 != inventoryCount {
		return fmt.Errorf("rotation witness check 4: %w", audit.ErrInvalid)
	}
	if activeIndex > curIndex {
		activeIndex = 0
	}
	// The original tail deletion is reverse ordinal, one native call at a time.
	for i := inventoryCount - 1; i > curIndex; i-- {
		var target, originalUser uuid.UUID
		var expectedPosition int
		err = c.tx.QueryRowContext(c.ctx, `SELECT resource_key::uuid,(before_value->>'user_id')::uuid,(before_value->>'position')::integer FROM pg_temp.sd8_user_delete_witness WHERE root_ordinal=$1 AND resource_type='rotation_participant' AND before_value->>'rotation_id'=$2 AND original_ordinal=$3`, c.ordinal, rotation.String(), i).Scan(&target, &originalUser, &expectedPosition)
		if err != nil {
			return err
		}
		var actualID, actualRotation, actualUser uuid.UUID
		var actualPosition int
		var version uint32
		err = c.tx.QueryRowContext(c.ctx, `DELETE FROM rotation_participants WHERE id=$1 RETURNING id,rotation_id,user_id,position,xmin::text::bigint`, target).Scan(&actualID, &actualRotation, &actualUser, &actualPosition, &version)
		if err != nil {
			return err
		}
		if actualID != target || actualRotation != rotation || actualUser != originalUser || actualPosition != expectedPosition || version == 0 {
			return fmt.Errorf("rotation witness check 5: %w", audit.ErrInvalid)
		}
		if _, err = c.tx.ExecContext(c.ctx, `UPDATE pg_temp.sd8_user_delete_witness SET after_value='null',emit=true WHERE root_ordinal=$1 AND resource_type='rotation_participant' AND resource_key=$2`, c.ordinal, target.String()); err != nil {
			return err
		}
	}
	var activePart uuid.UUID
	var activePosition int64
	err = c.tx.QueryRowContext(c.ctx, `SELECT resource_key::uuid,(before_value->>'position')::bigint FROM pg_temp.sd8_user_delete_witness WHERE root_ordinal=$1 AND resource_type='rotation_participant' AND before_value->>'rotation_id'=$2 AND original_ordinal=$3`, c.ordinal, rotation.String(), activeIndex).Scan(&activePart, &activePosition)
	if err != nil {
		return err
	}
	// For an all-U rotation the trigger removed State; this update still executes
	// and affects zero rows, exactly as the original algorithm does.
	stateResult, err := c.tx.ExecContext(c.ctx, `UPDATE rotation_state SET position=$2,rotation_participant_id=$3 WHERE rotation_id=$1`, rotation, activeIndex, activePart)
	if err != nil {
		return err
	}
	n, err := stateResult.RowsAffected()
	if err != nil {
		return err
	}
	wantStateRows := int64(1)
	if curIndex < 0 {
		wantStateRows = 0
	}
	if n != wantStateRows {
		return audit.ErrInvalid
	}
	var actualCount int64
	var survivorCount int64
	var mismatch bool
	err = c.tx.QueryRowContext(c.ctx, `SELECT participant_count,(SELECT count(*) FROM rotation_participants WHERE rotation_id=$1) FROM rotations WHERE id=$1`, rotation).Scan(&actualCount, &survivorCount)
	if err != nil {
		return err
	}
	if actualCount != curIndex+1 || survivorCount != actualCount {
		return fmt.Errorf("rotation witness check 6: %w", audit.ErrInvalid)
	}
	err = c.tx.QueryRowContext(c.ctx, `SELECT EXISTS(SELECT FROM pg_temp.sd8_user_delete_witness w LEFT JOIN rotation_participants p ON p.id=w.resource_key::uuid
 WHERE w.root_ordinal=$1 AND w.resource_type='rotation_participant' AND w.before_value->>'rotation_id'=$2 AND
 ((w.original_ordinal<=$3 AND (p.id IS NULL OR p.rotation_id::text<>$2 OR p.position<>(w.before_value->>'position')::integer OR p.user_id<>(coalesce(nullif(w.after_value,'null'),w.before_value)->>'user_id')::uuid OR p.xmin::text<>(coalesce(nullif(w.after_value,'null'),w.before_value)->>'row_version')))
 OR (w.original_ordinal>$3 AND p.id IS NOT NULL)))`, c.ordinal, rotation.String(), curIndex).Scan(&mismatch)
	if err != nil {
		return err
	}
	if mismatch {
		return fmt.Errorf("rotation witness check 7: %w", audit.ErrInvalid)
	}
	_, err = c.tx.ExecContext(c.ctx, `UPDATE pg_temp.sd8_user_delete_witness SET after_value=jsonb_build_object('rotation_id',$2::uuid,'participant_count',$3::bigint),emit=$4 WHERE root_ordinal=$1 AND resource_type='rotation_participant_count' AND resource_key=$2::uuid::text`, c.ordinal, rotation.String(), actualCount, actualCount != originalCount)
	if err != nil {
		return err
	}
	var stateAfter []byte
	err = c.tx.QueryRowContext(c.ctx, `SELECT `+projectionSQL(stateFields)+` FROM rotation_state b WHERE rotation_id=$1`, rotation).Scan(&stateAfter)
	if errors.Is(err, sql.ErrNoRows) {
		if actualCount != 0 {
			return fmt.Errorf("rotation witness check 8: %w", audit.ErrInvalid)
		}
		stateAfter = []byte("null")
	} else if err != nil {
		return err
	}
	if actualCount == 0 && string(stateAfter) != "null" {
		return fmt.Errorf("rotation witness check 9: %w", audit.ErrInvalid)
	}
	if actualCount > 0 {
		if err = audit.ValidateSnapshot("rotation_state", strconv.FormatInt(stateID, 10), stateAfter); err != nil {
			return err
		}
		var actual struct {
			RotationID    uuid.UUID `json:"rotation_id"`
			ParticipantID uuid.UUID `json:"participant_id"`
			Position      int64     `json:"position"`
		}
		// The existing state trigger derives actual position from Participant;
		// preserve that trigger semantics rather than equating it with ordinal.
		if json.Unmarshal(stateAfter, &actual) != nil || actual.RotationID != rotation || actual.ParticipantID != activePart || actual.Position != activePosition {
			return audit.ErrInvalid
		}
		var before, after map[string]json.RawMessage
		if json.Unmarshal(stateBefore, &before) != nil || json.Unmarshal(stateAfter, &after) != nil || !bytes.Equal(before["shift_start"], after["shift_start"]) || !bytes.Equal(before["version"], after["version"]) {
			return audit.ErrInvalid
		}
	}
	_, err = c.tx.ExecContext(c.ctx, `UPDATE pg_temp.sd8_user_delete_witness SET after_value=$3::jsonb,emit=(before_value-'row_version') IS DISTINCT FROM CASE WHEN jsonb_typeof($3::jsonb)='object' THEN $3::jsonb-'row_version' ELSE $3::jsonb END WHERE root_ordinal=$1 AND resource_type='rotation_state' AND resource_key=$2`, c.ordinal, strconv.FormatInt(stateID, 10), string(stateAfter))
	return err
}
