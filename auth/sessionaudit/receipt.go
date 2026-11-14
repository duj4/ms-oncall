package sessionaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/target/goalert/permission"
	useraudit "github.com/target/goalert/user/deleteaudit"
	"github.com/target/goalert/util/sqlutil"
)

// Receipt cannot be constructed from a selector or count. Its private spool is
// populated by DELETE RETURNING on its bound business transaction, exactly once.
type Receipt struct {
	tx    *sql.Tx
	event Event
	count Count
	used  bool
}

func RevokeSelected(ctx context.Context, tx *sql.Tx, e Event, ids ...string) (*Receipt, error) {
	if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
		return nil, err
	}
	if e.SelectionMode != "selected_sessions" {
		return nil, ErrInvalid
	}
	if permission.Admin(ctx) {
		return revoke(ctx, tx, e, `id=ANY($1)`, []any{sqlutil.UUIDArray(ids)})
	}
	return revoke(ctx, tx, e, `user_id=$1 AND id=ANY($2::uuid[])`, []any{permission.UserNullUUID(ctx), sqlutil.UUIDArray(ids)})
}
func RevokeOtherSelf(ctx context.Context, tx *sql.Tx, e Event) (*Receipt, error) {
	if err := permission.LimitCheckAny(ctx, permission.Admin, permission.MatchUser(permission.UserID(ctx))); err != nil {
		return nil, err
	}
	src := permission.Source(ctx)
	if e.SelectionMode != "other_sessions_of_current_user" || e.ActorKind != "human" || e.ActorID == nil || e.ActorID.String() != permission.UserID(ctx) || src == nil {
		return nil, ErrInvalid
	}
	current, err := uuid.Parse(src.ID)
	if err != nil || current == uuid.Nil {
		return nil, ErrInvalid
	}
	return revoke(ctx, tx, e, `user_id=$1 AND id!=$2`, []any{permission.UserNullUUID(ctx), current})
}

func revoke(ctx context.Context, tx *sql.Tx, e Event, predicate string, args []any) (*Receipt, error) {
	if tx == nil || e.Validate() != nil || e.ActorKind == "unknown" || e.RecordKind != "attempt_observation" {
		return nil, ErrInvalid
	}
	// Access the new schema before the first mutation. Missing schema fails closed.
	var ready bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='public.auth_user_sessions'::regclass AND attname='audit_resource_id' AND NOT attisdropped) AND to_regclass('public.user_session_revoke_audit_events') IS NOT NULL AND to_regclass('public.user_session_revoke_audit_details') IS NOT NULL`).Scan(&ready); err != nil || !ready {
		return nil, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE session_revoke_owners(owner_key text PRIMARY KEY,owner_id uuid,org_id uuid,resolution text NOT NULL DEFAULT 'unknown') ON COMMIT DROP`); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO pg_temp.session_revoke_owners(owner_key,owner_id) SELECT DISTINCT coalesce(user_id::text,''),user_id FROM public.auth_user_sessions WHERE `+predicate, args...); err != nil {
		return nil, err
	}
	// Bounded Go memory. Each page is closed before issuing any other SQL on this
	// connection. Lock owner/assignment/org before DELETE takes Session row locks.
	last := ""
	first := true
	for {
		rows, err := tx.QueryContext(ctx, `SELECT owner_key,owner_id FROM pg_temp.session_revoke_owners WHERE $1 OR owner_key>$2 ORDER BY owner_key LIMIT 256`, first, last)
		if err != nil {
			return nil, err
		}
		type owner struct {
			key string
			id  uuid.NullUUID
		}
		page := make([]owner, 0, 256)
		for rows.Next() {
			var o owner
			if err = rows.Scan(&o.key, &o.id); err != nil {
				break
			}
			page = append(page, o)
		}
		scanErr := err
		rowErr := rows.Err()
		closeErr := rows.Close()
		if scanErr != nil || rowErr != nil || closeErr != nil {
			return nil, ErrInvalid
		}
		if len(page) == 0 {
			break
		}
		for _, o := range page {
			if o.id.Valid {
				snapshot, err := useraudit.SnapshotOrganization(ctx, tx, o.id.UUID)
				if err != nil {
					return nil, err
				}
				if _, err = tx.ExecContext(ctx, `UPDATE pg_temp.session_revoke_owners SET org_id=$2,resolution=$3 WHERE owner_key=$1`, o.key, ID(snapshot.ID), snapshot.Resolution); err != nil {
					return nil, err
				}
			}
		}
		last = page[len(page)-1].key
		first = false
	}
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE session_revoke_receipt(session_audit_id uuid PRIMARY KEY,target_user_id uuid) ON COMMIT DROP`); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `WITH revoked AS (DELETE FROM public.auth_user_sessions WHERE `+predicate+` RETURNING audit_resource_id,user_id) INSERT INTO pg_temp.session_revoke_receipt SELECT audit_resource_id,user_id FROM revoked`, args...); err != nil {
		return nil, err
	}
	var count int64
	var covered bool
	if err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(bool_and(o.owner_key IS NOT NULL),true) FROM pg_temp.session_revoke_receipt r LEFT JOIN pg_temp.session_revoke_owners o ON o.owner_key=coalesce(r.target_user_id::text,'')`).Scan(&count, &covered); err != nil {
		return nil, err
	}
	if !covered || count < 0 {
		return nil, ErrInvalid
	}
	return &Receipt{tx: tx, event: e, count: Count(count)}, nil
}

const eventColumns = `schema_version,event_id,request_id,execution_id,attempt_id,record_kind,operation,selection_mode,actor_kind,actor_id,initiator_kind,initiator_user_id,home_organization_id,authority_source,authority_role,organization_role,affected_count,outcome,reason_code,occurred_at,recorded_at`
const detailColumns = `event_id,effect_ordinal,session_audit_id,target_user_id,target_organization_id,target_org_resolution,provenance,deletion_mechanism,cause`

func appendObject(ctx context.Context, tx *sql.Tx, table, columns string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return ErrInvalid
	}
	result, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO public.%s (%s) SELECT %s FROM jsonb_populate_record(NULL::public.%s,$1::jsonb)`, table, columns, columns, table), string(raw))
	if err != nil {
		return ErrUnavailable
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrUnavailable
	}
	return nil
}
func AppendObservation(ctx context.Context, tx *sql.Tx, e Event) error {
	if tx == nil || e.RecordKind != "attempt_observation" || e.Validate() != nil {
		return ErrInvalid
	}
	return appendObject(ctx, tx, "user_session_revoke_audit_events", eventColumns, e)
}
func (r *Receipt) Append(ctx context.Context, tx *sql.Tx, binding Event) error {
	if r == nil || r.used || tx == nil || tx != r.tx || r.event != binding {
		return ErrInvalid
	}
	r.used = true
	if r.count == 0 {
		return nil
	}
	e := r.event
	e.RecordKind = "success_witness"
	e.Outcome = "committed"
	e.Reason = "revoked"
	e.AffectedCount = r.count
	if e.Validate() != nil {
		return ErrInvalid
	}
	if err := appendObject(ctx, tx, "user_session_revoke_audit_events", eventColumns, e); err != nil {
		return err
	}
	last := uuid.Nil
	ordinal := Count(0)
	for {
		rows, err := tx.QueryContext(ctx, `SELECT r.session_audit_id,r.target_user_id,o.org_id,o.resolution FROM pg_temp.session_revoke_receipt r JOIN pg_temp.session_revoke_owners o ON o.owner_key=coalesce(r.target_user_id::text,'') WHERE $1 OR r.session_audit_id>$2 ORDER BY r.session_audit_id LIMIT 256`, ordinal == 0, last)
		if err != nil {
			return ErrUnavailable
		}
		page := make([]Detail, 0, 256)
		for rows.Next() {
			var d Detail
			var user, org uuid.NullUUID
			if err = rows.Scan(&d.SessionAuditID, &user, &org, &d.TargetOrgResolution); err != nil {
				break
			}
			if user.Valid {
				v := user.UUID
				d.TargetUserID = &v
			}
			if org.Valid {
				v := org.UUID
				d.TargetOrganizationID = &v
			}
			page = append(page, d)
		}
		scanErr := err
		rowErr := rows.Err()
		closeErr := rows.Close()
		if scanErr != nil || rowErr != nil || closeErr != nil {
			return ErrInvalid
		}
		if len(page) == 0 {
			break
		}
		for _, d := range page {
			d.EventID = e.EventID
			d.Ordinal = ordinal
			d.Provenance = "EXPLICIT"
			d.DeletionMechanism = "explicit_sql"
			d.Cause = "explicit_target"
			if e.SelectionMode == "other_sessions_of_current_user" {
				d.Cause = "end_other_self_sessions"
			}
			if d.Validate(e) != nil {
				return ErrInvalid
			}
			if err = appendObject(ctx, tx, "user_session_revoke_audit_details", detailColumns, d); err != nil {
				return err
			}
			ordinal++
			last = d.SessionAuditID
		}
	}
	if ordinal != r.count {
		return ErrInvalid
	}
	return nil
}
