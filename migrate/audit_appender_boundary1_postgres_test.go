package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	pgdump "github.com/target/goalert/devtools/pgdump-lite"
	ep "github.com/target/goalert/escalation/deleteaudit"
	svc "github.com/target/goalert/service/deleteaudit"
)

// These are audit-only inputs accepted by the production closed DTOs. They do
// not claim to execute DeleteAll, consume a Guard, or prove business deletion.
type boundary1Input struct {
	id                    uuid.UUID
	raw                   []byte
	validate              func() error
	append                func(context.Context, *sql.Tx) error
	capacity, unavailable error
}
type boundary1Kind struct {
	name, table, validSQL string
	build                 func(*testing.T, int, bool, int) boundary1Input
}

func boundary1Kinds() []boundary1Kind {
	return []boundary1Kind{
		{"service", "service_delete_audit_events", "service_delete_effects_valid($1::jsonb,$2)", func(t *testing.T, n int, favorite bool, shorter int) boundary1Input {
			e := serviceDeleteDBEvent()
			owner, org := uuid.New(), e.TargetOrganizationID
			for i := 0; i < n; i++ {
				id := int64(1000000000000000000) + int64(i)
				if i < shorter {
					id = 100000000000000000 + int64(i)
				}
				f := svc.Effect{EffectID: uuid.New(), ResourceType: svc.Alert, ResourceNumericID: &id, OwnerOrgResolution: "not_applicable", TargetOrganizationID: org, Relation: "service.alert", Change: "deleted", Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: "service_delete"}
				if favorite {
					f.ResourceType, f.OwnerUserID, f.OwnerOrganizationID, f.OwnerOrgResolution, f.Relation, f.Change = svc.ServiceFavorite, &owner, &org, "known_normal", "service.favorite", "relationship_removed"
				}
				e.Effects = append(e.Effects, f)
			}
			e = e.Canonical()
			raw, err := json.Marshal(e.Effects)
			require.NoError(t, err)
			return boundary1Input{e.EventID, raw, e.Validate, func(ctx context.Context, tx *sql.Tx) error { return svc.Append(ctx, tx, e) }, svc.ErrCapacity, svc.ErrUnavailable}
		}},
		{"ep", "escalation_policy_delete_audit_events", "escalation_policy_delete_effects_valid($1::jsonb,$2,$3)", func(t *testing.T, n int, favorite bool, shorter int) boundary1Input {
			e := sd5SchemaEvent()
			owner, org := uuid.New(), e.TargetOrganizationID
			for i := 0; i < n; i++ {
				f := sd5SchemaEffect(e, i)
				if favorite {
					id := int64(1000000000000000000) + int64(i)
					if i < shorter {
						id = 100000000000000000 + int64(i)
					}
					f.ResourceType, f.ResourceUUID, f.StepNumber, f.ResourceNumericID, f.OwnerUserID, f.OwnerOrganizationID, f.OwnerOrgResolution, f.Relation, f.Change = ep.Favorite, nil, nil, &id, &owner, &org, "known_normal", "escalation_policy.favorite", "relationship_removed"
				}
				e.Effects = append(e.Effects, f)
			}
			e = e.Canonical()
			raw, err := json.Marshal(e.Effects)
			require.NoError(t, err)
			return boundary1Input{e.EventID, raw, e.Validate, func(ctx context.Context, tx *sql.Tx) error { return ep.Append(ctx, tx, e) }, ep.ErrCapacity, ep.ErrUnavailable}
		}},
	}
}

func boundary1DB(t *testing.T) (context.Context, *sql.DB) {
	t.Helper()
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	require.Len(t, Names(), 309)
	require.NoError(t, VerifyAll(ctx, uri))
	require.NoError(t, VerifyIsLatest(ctx, uri))
	var applied, tail int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*),max(canonical_position) FROM ms_oncall_migration_provenance`).Scan(&applied, &tail))
	require.Equal(t, 309, applied)
	require.Equal(t, 309, tail)
	var up int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gorp_migrations`).Scan(&up))
	require.Equal(t, 309, up)
	conn, err := pgx.Connect(ctx, uri)
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close(ctx)) }()
	schema, err := pgdump.DumpSchema(ctx, conn)
	require.NoError(t, err)
	canonical, err := os.ReadFile("schema.sql")
	require.NoError(t, err)
	headerAndSchema := strings.SplitN(string(canonical), "\n\n", 2)
	require.Len(t, headerAndSchema, 2)
	require.True(t, headerAndSchema[1] == schema.String(), "fresh309 canonical schema body differs")
	t.Logf("fresh Migration0->309; Applied UP=%d canonical tail=%d VerifyAll/Latest PASS", up, tail)
	return ctx, db
}

func boundary1PG(t *testing.T, ctx context.Context, db *sql.DB, k boundary1Kind, in boundary1Input) (int, int, bool) {
	t.Helper()
	// Derive safe target IDs from the closed JSON; no raw credential identities.
	var items []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(in.raw, &items))
	require.NotEmpty(t, items)
	var org, root string
	require.NoError(t, json.Unmarshal(items[0]["target_organization_id"], &org))
	args := []any{string(in.raw), org}
	if k.name == "ep" {
		require.NoError(t, json.Unmarshal(items[0]["root_id"], &root))
		args = []any{string(in.raw), root, org}
	}
	var count, bytes int
	var valid bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_array_length($1::jsonb),octet_length($1::jsonb::text),`+k.validSQL, args...).Scan(&count, &bytes, &valid))
	return count, bytes, valid
}

// Existing committed evidence and all row counts are read through an explicitly
// reserved independent connection. A staged control must also roll back when
// Append rejects. No business table is mutated by this test.
func boundary1Persist(t *testing.T, ctx context.Context, db *sql.DB, k boundary1Kind, in boundary1Input, want error, sqlRejected bool) {
	t.Helper()
	observer, err := db.Conn(ctx)
	require.NoError(t, err)
	defer func() { require.NoError(t, observer.Close()) }()
	seed := k.build(t, 0, false, 0)
	seedTx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = seedTx.Rollback() })
	require.NoError(t, seed.append(ctx, seedTx))
	require.NoError(t, seedTx.Commit())
	var seedBefore, seedAfter string
	require.NoError(t, observer.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM `+k.table+` e WHERE event_id=$1`, seed.id).Scan(&seedBefore))
	var before int
	require.NoError(t, observer.QueryRowContext(ctx, `SELECT count(*) FROM `+k.table).Scan(&before))
	control := k.build(t, 0, false, 0)
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	require.NoError(t, control.append(ctx, tx))
	if want == nil {
		require.NoError(t, in.append(ctx, tx))
	} else {
		require.ErrorIs(t, in.append(ctx, tx), want)
	}
	var visible int
	require.NoError(t, observer.QueryRowContext(ctx, `SELECT count(*) FROM `+k.table+` WHERE event_id IN ($1,$2)`, in.id, control.id).Scan(&visible))
	require.Zero(t, visible, "uncommitted success evidence must not be visible")
	var one int
	err = tx.QueryRowContext(ctx, `SELECT 1`).Scan(&one)
	if sqlRejected {
		var pg *pgconn.PgError
		require.ErrorAs(t, err, &pg)
		require.Equal(t, "25P02", pg.Code)
	} else {
		require.NoError(t, err)
		require.Equal(t, 1, one)
	}
	if want == nil {
		require.NoError(t, tx.Commit())
	} else {
		require.NoError(t, tx.Rollback())
	}
	var after, effects int
	require.NoError(t, observer.QueryRowContext(ctx, `SELECT count(*) FROM `+k.table).Scan(&after))
	if want == nil {
		require.Equal(t, before+2, after)
		require.NoError(t, observer.QueryRowContext(ctx, `SELECT jsonb_array_length(effects) FROM `+k.table+` WHERE event_id=$1`, in.id).Scan(&effects))
		var decoded []json.RawMessage
		require.NoError(t, json.Unmarshal(in.raw, &decoded))
		require.Len(t, decoded, effects)
		var stored int
		require.NoError(t, observer.QueryRowContext(ctx, `SELECT octet_length(effects::text) FROM `+k.table+` WHERE event_id=$1`, in.id).Scan(&stored))
		var measured int
		require.NoError(t, observer.QueryRowContext(ctx, `SELECT octet_length($1::jsonb::text)`, string(in.raw)).Scan(&measured))
		require.Equal(t, measured, stored)
	} else {
		require.Equal(t, before, after, "no partial, false success or B2 effects rows")
	}
	require.NoError(t, observer.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM `+k.table+` e WHERE event_id=$1`, seed.id).Scan(&seedAfter))
	require.Equal(t, seedBefore, seedAfter)
	require.NoError(t, db.PingContext(ctx))
}

func TestPostgresAuditAppenderBoundary1Count(t *testing.T) {
	for _, k := range boundary1Kinds() {
		t.Run(k.name, func(t *testing.T) {
			ctx, db := boundary1DB(t)
			for _, n := range []int{16383, 16384, 16385} {
				t.Run(fmt.Sprint(n), func(t *testing.T) {
					in := k.build(t, n, false, 0)
					count, bytes, valid := boundary1PG(t, ctx, db, k, in)
					require.Equal(t, n, count)
					require.LessOrEqual(t, bytes, 8388608)
					require.Equal(t, n <= 16384, valid)
					var want error
					if n > 16384 {
						want = in.capacity
						require.ErrorIs(t, in.validate(), want)
					} else {
						require.NoError(t, in.validate())
					}
					boundary1Persist(t, ctx, db, k, in, want, false)
					t.Logf("effects=%d compact=%d PG effects::text=%d SQL valid=%t; rejection=%v; count overflow PRE-PERSISTENCE; audit-only persistence/rollback verified", count, len(in.raw), bytes, valid, want)
				})
			}
		})
	}
}

func TestPostgresAuditAppenderBoundary1Bytes(t *testing.T) {
	for _, k := range boundary1Kinds() {
		t.Run(k.name, func(t *testing.T) {
			ctx, db := boundary1DB(t)
			for _, metric := range []string{"pg-text", "go-compact"} {
				t.Run(metric, func(t *testing.T) {
					one := k.build(t, 1, true, 0)
					_, unit, _ := boundary1PG(t, ctx, db, k, one)
					if metric == "go-compact" {
						unit = len(one.raw) - 1
					}
					for _, target := range []int{8388607, 8388608, 8388609} {
						t.Run(fmt.Sprint(target), func(t *testing.T) {
							n := (target + unit - 1) / unit
							// A singleton JSONB array has the same length as its object plus
							// comma+space; compact arrays instead have one extra closing bracket.
							if metric == "go-compact" {
								n = (target - 1 + unit - 1) / unit
							}
							base := k.build(t, n, true, 0)
							_, bytes, _ := boundary1PG(t, ctx, db, k, base)
							size := bytes
							if metric == "go-compact" {
								size = len(base.raw)
							}
							shorter := size - target
							require.GreaterOrEqual(t, shorter, 0)
							require.Less(t, shorter, n)
							in := k.build(t, n, true, shorter)
							count, bytes, valid := boundary1PG(t, ctx, db, k, in)
							require.Less(t, count, 16384)
							var want error
							sqlRejected := false
							if metric == "pg-text" {
								require.Equal(t, target, bytes)
								require.Less(t, len(in.raw), 8388608)
								require.NoError(t, in.validate())
								require.Equal(t, target <= 8388608, valid)
								if !valid {
									want = in.unavailable
									sqlRejected = true
								}
							} else {
								require.Equal(t, target, len(in.raw))
								require.Greater(t, bytes, 8388608)
								require.False(t, valid)
								if target > 8388608 {
									want = in.capacity
									require.ErrorIs(t, in.validate(), want)
								} else {
									require.NoError(t, in.validate())
									want = in.unavailable
									sqlRejected = true
								}
							}
							boundary1Persist(t, ctx, db, k, in, want, sqlRejected)
							t.Logf("metric=%s effects=%d compact=%d PG effects::text=%d SQL valid=%t; rejection=%v sql_aborted=%t; audit-only rollback/seed preservation verified", metric, count, len(in.raw), bytes, valid, want, sqlRejected)
						})
					}
				})
			}
		})
	}
}
