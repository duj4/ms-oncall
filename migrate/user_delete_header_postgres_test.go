package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/organization"
	audit "github.com/target/goalert/user/deleteaudit"
)

// Use the raw JSON at both SQL boundaries: Append would reject it in Go first.
func sd8InsertRawHeader(ctx context.Context, tx *sql.Tx, raw []byte) error {
	// Select every canonical column so a missing required field becomes SQL
	// NULL rather than silently receiving a table default during this probe.
	columnsJSON, err := json.Marshal(audit.Event{})
	if err != nil {
		return err
	}
	var h map[string]json.RawMessage
	if err := json.Unmarshal(columnsJSON, &h); err != nil {
		return err
	}
	cols := make([]string, 0, len(h))
	for k := range h {
		cols = append(cols, k)
	}
	sort.Strings(cols)
	columns := strings.Join(cols, ",")
	values := append([]string{}, cols...)
	for i, col := range cols {
		// jsonb_populate_record maps JSON null to SQL NULL, including for
		// jsonb columns. Preserve the legitimate JSON-null empty before.
		if col == "before_context" || col == "manifest" || col == "related_explicit_events" {
			values[i] = "($1::jsonb)->'" + col + "'"
		}
	}
	_, err = tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO user_delete_audit_events(%s) SELECT %s FROM jsonb_populate_record(NULL::user_delete_audit_events,$1::jsonb)`, columns, strings.Join(values, ",")), string(raw))
	return err
}

func TestPostgresUserDeleteHeaderNullTypes(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, 302)
	// Hold a dedicated observer throughout each writer's transaction. A pooled
	// QueryRow alone could reuse the writer's backend after Commit.
	observer, err := db.Conn(ctx)
	require.NoError(t, err)
	defer func() { require.NoError(t, observer.Close()) }()
	var observerPID int
	require.NoError(t, observer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&observerPID))

	type invalid struct{ id, field, value string }
	var cases []invalid
	for _, role := range []struct{ field, prefix string }{{"user_role", "user"}, {"organization_role", "org"}} {
		for _, v := range []struct{ id, value string }{
			{"null", "null"}, {"missing", ""}, {"number", "1"}, {"boolean", "true"},
			{"array", `[]`}, {"object", `{}`}, {"enum", `"INVALID"`},
		} {
			cases = append(cases, invalid{"FIX1-" + role.prefix + "-" + v.id, "before." + role.field, v.value})
		}
	}
	cases = append(cases,
		invalid{"FIX1-N09-assignment-absent-version", "before.assignment_row_version", "1"},
		invalid{"FIX1-N09-assignment-absent-role", "before.organization_role", `"ORG_MEMBER"`},
		invalid{"FIX1-N09-assignment-present-null-version", "before.assignment_present", "true"},
		invalid{"FIX1-N09-assignment-present-null-role", "assigned.organization_role", "null"},
		invalid{"FIX1-N09-assignment-present-null-org", "normal.target_organization_id", "null"},
		invalid{"FIX1-N10-manifest-null", "manifest", `{"user_session":null}`},
		invalid{"FIX1-N10-manifest-string", "manifest", `{"user_session":"1"}`},
		invalid{"FIX1-N10-ref-null", "related_explicit_events", `[{"event_id":"11111111-1111-4111-8111-111111111111","resource_id":"22222222-2222-4222-8222-222222222222","resource_type":null}]`},
		invalid{"FIX1-N10-ref-object", "related_explicit_events", `[{"event_id":"11111111-1111-4111-8111-111111111111","resource_id":"22222222-2222-4222-8222-222222222222","resource_type":{}}]`},
	)
	for _, field := range []string{"version", "user_id", "row_version", "target_org_resolution"} {
		cases = append(cases, invalid{"FIX1-before-" + field + "-null", "before." + field, "null"})
	}
	for _, field := range []string{"operation", "schema_version", "record_kind", "authority_source", "authority_role", "organization_role", "outcome", "reason_code", "provenance", "deletion_mechanism", "cause", "occurred_at"} {
		cases = append(cases, invalid{"FIX1-header-" + field + "-null", field, "null"})
		cases = append(cases, invalid{"FIX1-header-" + field + "-missing", field, ""})
		cases = append(cases, invalid{"FIX1-header-" + field + "-type", field, "{}"})
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			e := sd8SchemaEvent().Canonical()
			parts := strings.SplitN(tc.field, ".", 2)
			if parts[0] == "assigned" || parts[0] == "normal" {
				xmin := uint32(1)
				e.BeforeContext.AssignmentPresent, e.BeforeContext.AssignmentRowVersion = true, &xmin
				if parts[0] == "normal" {
					org := uuid.New()
					e.TargetOrganizationID, e.BeforeContext.TargetOrganizationID = &org, &org
					e.TargetOrgResolution, e.BeforeContext.TargetOrgResolution = "known_normal", "known_normal"
					e.BeforeContext.OrganizationRole = "ORG_MEMBER"
				}
			}
			raw, err := json.Marshal(e)
			require.NoError(t, err)
			var h, b map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(raw, &h))
			require.NoError(t, json.Unmarshal(h["before_context"], &b))
			object, key := h, tc.field
			if len(parts) == 2 {
				object, key = b, parts[1]
			}
			if tc.value == "" {
				delete(object, key)
			} else {
				object[key] = json.RawMessage(tc.value)
			}
			h["before_context"], err = json.Marshal(b)
			require.NoError(t, err)
			raw, err = json.Marshal(h)
			require.NoError(t, err)
			var decoded audit.Event
			goErr := json.Unmarshal(raw, &decoded)
			if goErr == nil {
				goErr = decoded.Validate()
			}
			require.Error(t, goErr, "Go decoding/validation must reject")
			var accepted sql.NullBool
			require.NoError(t, observer.QueryRowContext(ctx, `SELECT user_delete_header_valid($1::jsonb)`, string(raw)).Scan(&accepted))
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			var writerPID int
			require.NoError(t, tx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&writerPID))
			require.NotEqual(t, observerPID, writerPID)
			insertErr := sd8InsertRawHeader(ctx, tx, raw)
			commitErr := tx.Commit() // Also observe Commit on an aborted INSERT.
			var durable int
			require.NoError(t, observer.QueryRowContext(ctx, `SELECT count(*) FROM user_delete_audit_events WHERE event_id=$1`, e.EventID).Scan(&durable))
			code := "none"
			var pg *pgconn.PgError
			if assert.ErrorAs(t, insertErr, &pg) {
				code = pg.Code
				assert.Contains(t, []string{"22", "23"}, code[:2])
			}
			t.Logf("GoReject=true SQLValidatorAccept=%t SQLResultNonNull=%t InsertSucceeded=%t CommitSucceeded=%t durable_rows=%d SQLSTATE=%s observer_pid=%d writer_pid=%d", accepted.Bool, accepted.Valid, insertErr == nil, commitErr == nil, durable, code, observerPID, writerPID)
			assert.True(t, accepted.Valid)
			assert.False(t, accepted.Bool)
			assert.Error(t, commitErr)
			assert.Zero(t, durable)
		})
	}
}

func TestPostgresUserDeleteHeaderRejectRollsBackBusiness(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, 302)
	for _, field := range []string{"user_role", "organization_role"} {
		t.Run(field, func(t *testing.T) {
			e := sd8SchemaEvent().Canonical()
			_, err := db.ExecContext(ctx, `INSERT INTO users(id,name,role) VALUES($1,'SYNTHETIC_FIX1','user')`, e.RootID)
			require.NoError(t, err)
			observer, err := db.Conn(ctx)
			require.NoError(t, err)
			defer func() { require.NoError(t, observer.Close()) }()
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			var deleted uuid.UUID
			require.NoError(t, tx.QueryRowContext(ctx, `DELETE FROM users WHERE id=$1 RETURNING id`, e.RootID).Scan(&deleted))
			require.Equal(t, *e.RootID, deleted)
			raw, err := json.Marshal(e)
			require.NoError(t, err)
			var mutated string
			require.NoError(t, tx.QueryRowContext(ctx, `SELECT jsonb_set($1::jsonb,ARRAY['before_context',$2::text],'null'::jsonb)::text`, string(raw), field).Scan(&mutated))
			var pg *pgconn.PgError
			require.ErrorAs(t, sd8InsertRawHeader(ctx, tx, []byte(mutated)), &pg)
			require.Equal(t, "23514", pg.Code)
			require.Error(t, tx.Commit())
			var users, headers int
			require.NoError(t, observer.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM users WHERE id=$1),(SELECT count(*) FROM user_delete_audit_events WHERE event_id=$2)`, e.RootID, e.EventID).Scan(&users, &headers))
			require.Equal(t, 1, users)
			require.Zero(t, headers)
			t.Log("SQLSTATE=23514 CommitSucceeded=false business_rows=1 durable_headers=0")
		})
	}
}

func TestPostgresUserDeleteHeaderValidNullability(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, 302)
	for _, userRole := range []string{"user", "admin", "unknown"} {
		for _, orgRole := range []string{"unknown", "NONE", "ORG_ADMIN", "ORG_MEMBER"} {
			t.Run(userRole+"/"+orgRole, func(t *testing.T) {
				e := sd8SchemaEvent()
				xmin := uint32(1)
				e.BeforeContext.UserRole, e.BeforeContext.OrganizationRole = userRole, orgRole
				e.BeforeContext.AssignmentPresent, e.BeforeContext.AssignmentRowVersion = true, &xmin
				sd8CheckValidHeader(t, ctx, db, e)
			})
		}
	}
	for _, mode := range []string{"missing_assignment", "normal", "default", "self_delete", "failure_empty_before"} {
		t.Run(mode, func(t *testing.T) {
			e := sd8SchemaEvent()
			if mode == "normal" || mode == "default" {
				org, role, resolution := uuid.New(), "ORG_MEMBER", "known_normal"
				if mode == "default" {
					org, role, resolution = uuid.MustParse(organization.DefaultOrganizationID), "NONE", "known_default"
				}
				xmin := uint32(1)
				e.TargetOrganizationID, e.TargetOrgResolution = &org, resolution
				e.BeforeContext.TargetOrganizationID, e.BeforeContext.TargetOrgResolution = &org, resolution
				e.BeforeContext.AssignmentPresent, e.BeforeContext.AssignmentRowVersion, e.BeforeContext.OrganizationRole = true, &xmin, role
			}
			if mode == "self_delete" {
				home := uuid.New()
				e.ActorKind, e.ActorID, e.HomeOrganizationID = "human", e.RootID, &home
				e.AuthoritySource, e.AuthorityRole, e.OrganizationRole = "current_local_user_organization_at_admission", "platform_admin", "ORG_MEMBER"
			}
			if mode == "failure_empty_before" {
				e.RecordKind, e.Outcome, e.Reason = "attempt_observation", "tx_failed", "write_failed"
				e.RootID, e.RootOrdinal, e.BeforeContext = nil, nil, nil
				e.Provenance, e.DeletionMechanism, e.Cause = "", "", ""
			}
			sd8CheckValidHeader(t, ctx, db, e)
		})
	}
}

func sd8CheckValidHeader(t *testing.T, ctx context.Context, db *sql.DB, e audit.Event) {
	t.Helper()
	e = e.Canonical()
	require.NoError(t, e.Validate())
	raw, err := json.Marshal(e)
	require.NoError(t, err)
	var accepted bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT user_delete_header_valid($1::jsonb)`, string(raw)).Scan(&accepted))
	require.True(t, accepted)
	observer, err := db.Conn(ctx)
	require.NoError(t, err)
	defer func() { require.NoError(t, observer.Close()) }()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	require.NoError(t, sd8InsertRawHeader(ctx, tx, raw))
	require.NoError(t, tx.Commit())
	var durable int
	require.NoError(t, observer.QueryRowContext(ctx, `SELECT count(*) FROM user_delete_audit_events WHERE event_id=$1`, e.EventID).Scan(&durable))
	require.Equal(t, 1, durable)
	t.Log("GoAccept=true SQLAccept=true InsertSucceeded=true CommitSucceeded=true durable_rows=1")
}
