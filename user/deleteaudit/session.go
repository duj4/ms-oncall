package deleteaudit

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/target/goalert/util/sqlutil"
)

// sessionError keeps locator UUIDs and driver detail out of visible errors,
// while retaining the existing transaction owner's bounded retry SQLSTATEs.
func sessionError(err error) error {
	if err == nil {
		return nil
	}
	if pg := sqlutil.MapError(err); pg != nil && (pg.Code == "40001" || pg.Code == "40P01") {
		return &pgconn.PgError{Code: pg.Code, Message: "user.delete Session capture retry"}
	}
	return ErrInvalid
}

// CaptureSessions binds real locked rows to their SD9 identities. Locator PKs
// stay exclusively in a transaction-local consistency relation, never in the
// serialized witness. The caller owns the User deletion and transaction.
func CaptureSessions(ctx context.Context, tx *sql.Tx, root uuid.UUID, ordinal int, event uuid.UUID, org OrganizationSnapshot) error {
	if tx == nil || root == uuid.Nil || event == uuid.Nil || ordinal < 0 || ordinal >= MaxRoots || !ValidOrganization(ID(org.ID), org.Resolution) {
		return ErrInvalid
	}
	var present bool
	if err := tx.QueryRowContext(ctx, `SELECT true FROM users WHERE id=$1 FOR UPDATE`, root).Scan(&present); err != nil {
		return sessionError(err)
	}
	if !present {
		return ErrInvalid
	}
	_, err := tx.ExecContext(ctx, `CREATE TEMP TABLE IF NOT EXISTS sd8_user_session_identity (
 event_id uuid NOT NULL, root_ordinal integer NOT NULL, session_id uuid NOT NULL,
 audit_resource_id uuid NOT NULL, user_id uuid NOT NULL, row_version bigint NOT NULL,
 PRIMARY KEY(event_id,session_id), UNIQUE(audit_resource_id),
 CHECK(session_id<>audit_resource_id AND audit_resource_id<>'00000000-0000-0000-0000-000000000000')
 ) ON COMMIT DROP`)
	if err != nil {
		return sessionError(err)
	}
	// Reject anomalies before INSERT: a NOT NULL/UNIQUE/CHECK violation on
	// this private relation could put locator values in PostgreSQL error DETAIL.
	// The materialized CTE locks the complete set without returning any locator
	// to Go or placing one in an exception. All locks last until transaction end.
	var actualCount int64
	var invalid bool
	err = tx.QueryRowContext(ctx, `WITH locked AS MATERIALIZED (
 SELECT id,audit_resource_id FROM auth_user_sessions WHERE user_id=$1 ORDER BY id FOR UPDATE
 ) SELECT count(*),count(DISTINCT audit_resource_id)<>count(*) OR
 coalesce(bool_or(audit_resource_id IS NULL OR audit_resource_id='00000000-0000-0000-0000-000000000000'
 OR audit_resource_id=id OR EXISTS(SELECT FROM auth_user_sessions s WHERE s.id=locked.audit_resource_id)
 OR EXISTS(SELECT FROM pg_temp.sd8_user_session_identity i WHERE i.audit_resource_id=locked.audit_resource_id)),false)
 OR EXISTS(SELECT FROM pg_temp.sd8_user_session_identity WHERE event_id=$2)
 FROM locked`, root, event).Scan(&actualCount, &invalid)
	if err != nil {
		return sessionError(err)
	}
	if invalid {
		return ErrInvalid
	}
	_, err = tx.ExecContext(ctx, `WITH locked AS MATERIALIZED (
 SELECT id,audit_resource_id,user_id,xmin::text::bigint AS row_version
 FROM auth_user_sessions WHERE user_id=$1 ORDER BY id FOR UPDATE
 ) INSERT INTO pg_temp.sd8_user_session_identity SELECT $2,$3,id,audit_resource_id,user_id,row_version FROM locked`, root, event, ordinal)
	if err != nil {
		return sessionError(err)
	}
	// Full-set comparison includes missing/null/mismatched identities. There is
	// no inner join that can silently filter an anomalous Session from capture.
	err = tx.QueryRowContext(ctx, `WITH actual AS (SELECT id,audit_resource_id,user_id,xmin::text::bigint AS row_version FROM auth_user_sessions WHERE user_id=$1),
 captured AS (SELECT * FROM pg_temp.sd8_user_session_identity WHERE event_id=$2 AND root_ordinal=$3)
 SELECT EXISTS(SELECT FROM actual a FULL JOIN captured c ON a.id=c.session_id
 WHERE a.id IS NULL OR c.session_id IS NULL OR a.audit_resource_id IS DISTINCT FROM c.audit_resource_id
 OR a.user_id IS DISTINCT FROM c.user_id OR c.user_id<>$1 OR a.row_version<>c.row_version
 OR c.audit_resource_id=c.session_id OR c.audit_resource_id='00000000-0000-0000-0000-000000000000'
 OR EXISTS(SELECT FROM auth_user_sessions s WHERE s.id=c.audit_resource_id))`, root, event, ordinal).Scan(&invalid)
	if err != nil {
		return sessionError(err)
	}
	if invalid {
		return ErrInvalid
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO pg_temp.sd8_user_delete_witness(root_ordinal,resource_type,resource_key,before_value,organization_id,org_resolution)
 SELECT $2,'user_session',i.audit_resource_id::text,
 jsonb_build_object('version',2,'audit_resource_id',i.audit_resource_id,'user_id',i.user_id,'row_version',i.row_version),
 $3,$4 FROM pg_temp.sd8_user_session_identity i
 WHERE i.event_id=$1 AND i.root_ordinal=$2`, event, ordinal, ID(org.ID), org.Resolution)
	if err != nil {
		return sessionError(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return ErrInvalid
	}
	var captured int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_temp.sd8_user_session_identity WHERE event_id=$1 AND root_ordinal=$2`, event, ordinal).Scan(&captured); err != nil {
		return sessionError(err)
	}
	if n != captured || captured != actualCount {
		return ErrInvalid
	}
	return nil
}
