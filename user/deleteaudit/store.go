package deleteaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

const headerColumns = `schema_version,event_id,request_id,execution_id,attempt_id,record_kind,operation,root_type,root_id,root_ordinal,actor_kind,actor_id,home_organization_id,authority_source,authority_role,organization_role,target_organization_id,target_org_resolution,before_context,provenance,deletion_mechanism,cause,effect_count,effect_json_bytes,manifest,related_explicit_events,outcome,reason_code,occurred_at`

// Append stages a header. The deferred DB manifest gate also runs for direct
// inserts; a caller cannot commit a nonempty header without all its details.
func Append(ctx context.Context, tx *sql.Tx, event Event) error {
	e := event.Canonical()
	if err := e.Validate(); err != nil {
		return err
	}
	if tx == nil {
		return ErrUnavailable
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return ErrInvalid
	}
	cols := strings.Split(headerColumns, ",")
	selects := make([]string, len(cols))
	for i, col := range cols {
		selects[i] = "r." + col
		if col == "before_context" {
			selects[i] = "coalesce(r.before_context,'null'::jsonb)"
		}
	}
	r, err := tx.ExecContext(ctx, `INSERT INTO user_delete_audit_events (`+headerColumns+`) SELECT `+strings.Join(selects, ",")+` FROM jsonb_populate_record(NULL::user_delete_audit_events,$1::jsonb) r ON CONFLICT(event_id) DO NOTHING`, string(raw))
	if err != nil {
		return ErrUnavailable
	}
	n, err := r.RowsAffected()
	if err != nil {
		return ErrUnavailable
	}
	if n == 1 {
		return nil
	}
	var same bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM user_delete_audit_events e,jsonb_populate_record(NULL::user_delete_audit_events,$1::jsonb) r WHERE e.event_id=r.event_id AND (to_jsonb(e)-'recorded_at') IS NOT DISTINCT FROM (to_jsonb(r)-'recorded_at'))`, string(raw)).Scan(&same)
	if err != nil {
		return ErrUnavailable
	}
	if !same {
		return ErrConflict
	}
	return nil
}

// AppendReceipt streams complete verified effects. It never aggregates history
// into a Go slice or a single SQL JSON parameter and never commits a page.
func AppendReceipt(ctx context.Context, tx *sql.Tx, r Receipt) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if tx == nil {
		return ErrUnavailable
	}
	if err := Append(ctx, tx, r.Event); err != nil {
		return err
	}
	var budget Budget
	if err := budget.Reserve(600, 2*MaxHeaderBytes+100*2048); err != nil {
		return err
	}
	ordinal := int64(0)
	var total int64
	manifest := map[string]int64{}
	lastType, lastKey := "", ""
	for {
		if err := budget.Reserve(4*PageSize, 2*PageSize*MaxLeafBytes); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT resource_type,resource_key,payload::text,octet_length(payload::text) FROM pg_temp.sd8_user_delete_witness WHERE root_ordinal=$1 AND emit AND (resource_type,resource_key)>($2,$3) ORDER BY resource_type,resource_key LIMIT 256`, *r.Event.RootOrdinal, lastType, lastKey)
		if err != nil {
			return ErrUnavailable
		}
		type leaf struct {
			typ, key, raw string
			size          int64
		}
		page := make([]leaf, 0, PageSize)
		for rows.Next() {
			var f leaf
			if err = rows.Scan(&f.typ, &f.key, &f.raw, &f.size); err != nil {
				break
			}
			if len(f.raw) > MaxLeafBytes || f.size != int64(len(f.raw)) {
				err = ErrCapacity
				break
			}
			page = append(page, f)
		}
		if err == nil {
			err = rows.Err()
		}
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return ErrUnavailable
		}
		for _, row := range page {
			f, err := DecodeEffect([]byte(row.raw))
			if err != nil {
				return err
			}
			if err = f.Validate(*r.Event.RootID); err != nil {
				return err
			}
			if f.ResourceKey != row.key || f.ResourceType != row.typ || ordinal >= r.Event.EffectCount {
				return ErrInvalid
			}
			result, err := tx.ExecContext(ctx, `INSERT INTO user_delete_audit_effects(event_id,effect_ordinal,declared_effect_count,effect_id,resource_type,resource_key,transition_slot,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT(event_id,effect_ordinal) DO NOTHING`, r.Event.EventID, ordinal, r.Event.EffectCount, f.EffectID, f.ResourceType, f.ResourceKey, f.TransitionSlot, row.raw)
			if err != nil {
				return ErrUnavailable
			}
			n, err := result.RowsAffected()
			if err != nil {
				return ErrUnavailable
			}
			if n == 0 {
				var same bool
				err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM user_delete_audit_effects WHERE event_id=$1 AND effect_ordinal=$2 AND declared_effect_count=$3 AND effect_id=$4 AND resource_type=$5 AND resource_key=$6 AND transition_slot=$7 AND payload=$8::jsonb)`, r.Event.EventID, ordinal, r.Event.EffectCount, f.EffectID, f.ResourceType, f.ResourceKey, f.TransitionSlot, row.raw).Scan(&same)
				if err != nil {
					return ErrUnavailable
				}
				if !same {
					return ErrConflict
				}
			}
			if total > int64(^uint64(0)>>1)-row.size {
				return ErrCapacity
			}
			ordinal++
			total += row.size
			manifest[f.ResourceType]++
		}
		if err = budget.Release(4*PageSize, 2*PageSize*MaxLeafBytes); err != nil {
			return err
		}
		if len(page) == 0 {
			break
		}
		last := page[len(page)-1]
		lastType, lastKey = last.typ, last.key
	}
	if ordinal != r.Event.EffectCount || total != r.Event.EffectJSONBytes || len(manifest) != len(r.Event.Manifest) {
		return ErrInvalid
	}
	for typ, n := range manifest {
		if r.Event.Manifest[typ] != n {
			return ErrInvalid
		}
	}
	return nil
}
