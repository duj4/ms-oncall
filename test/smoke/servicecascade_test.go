package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/integrationkey"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/service"
	"github.com/target/goalert/service/deleteaudit"
	"github.com/target/goalert/test/smoke/harness"
)

func sd3Key(t *testing.T, h *harness.Harness, root string) (credential, safe uuid.UUID) {
	t.Helper()
	credential = uuid.New()
	require.NoError(t, h.App().DB().QueryRow(`INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,$3,'generic') RETURNING audit_resource_id`, credential, root, uuid.NewString()).Scan(&safe))
	return credential, safe
}
func sd3Alert(t *testing.T, h *harness.Harness, root, status string) int64 {
	t.Helper()
	var id int64
	var dedup any
	if status != "closed" {
		dedup = uuid.NewString()
	}
	require.NoError(t, h.App().DB().QueryRow(`INSERT INTO alerts(service_id,summary,status,dedup_key) VALUES($1,'SD3 synthetic',$2,$3) RETURNING id`, root, status, dedup).Scan(&id))
	return id
}
func sd3Effects(t *testing.T, h *harness.Harness, root string) []deleteaudit.Effect {
	t.Helper()
	var raw string
	var effects []deleteaudit.Effect
	require.NoError(t, h.App().DB().QueryRow(`SELECT effects::text FROM service_delete_audit_events WHERE service_id=$1 AND outcome='committed'`, root).Scan(&raw))
	require.NoError(t, json.Unmarshal([]byte(raw), &effects))
	return effects
}
func sd3Target(typ assignment.TargetType, id string) assignment.RawTarget {
	return assignment.RawTarget{Type: typ, ID: id}
}
func sd3App(h *harness.Harness) *graphqlapp.App {
	return &graphqlapp.App{DB: h.App().DB(), ServiceStore: h.App().ServiceStore, IntKeyStore: h.App().IntegrationKeyStore}
}
func sd3System() context.Context { return permission.SystemContext(context.Background(), "Engine") }

func TestServiceCascadePG01PG02PG10ExactEffects(t *testing.T) {
	for _, mode := range []string{"cascade", "explicit_after", "explicit_before"} {
		t.Run(mode, func(t *testing.T) {
			explicit := mode != "cascade"
			h := sd1Harness(t)
			ikSetAuthority(t, h, "ORG_MEMBER", true)
			db := h.App().DB()
			root := h.UUID("service-b")
			credential, safe := sd3Key(t, h, root)
			originalService, err := h.App().IntegrationKeyStore.GetServiceID(sd3System(), credential.String(), integrationkey.TypeGeneric)
			require.NoError(t, err)
			require.Equal(t, root, originalService)
			_, err = h.App().IntegrationKeyStore.GetServiceID(sd3System(), safe.String(), integrationkey.TypeGeneric)
			require.ErrorIs(t, err, sql.ErrNoRows, "the surrogate grants no credential capability")
			_, remaining := sd3Key(t, h, root)
			alertIDs := map[int64]bool{}
			for _, status := range []string{"triggered", "active", "closed"} {
				alertIDs[sd3Alert(t, h, root, status)] = true
			}
			owners := []uuid.UUID{uuid.MustParse(h.UUID("user-a")), uuid.New(), uuid.New()}
			favoriteIDs := map[int64]uuid.UUID{}
			for i, owner := range owners {
				if i > 0 {
					_, err := db.Exec(`INSERT INTO users(id,name,role) VALUES($1,'SD3 owner','user')`, owner)
					require.NoError(t, err)
				}
				if i == 1 {
					_, err := db.Exec(`INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,organization_role,mapping_outcome,matched_count,authoritative_evaluated_at,source_config_version) VALUES($1,$2,'DEFAULT','NONE','ZERO',0,now(),'sd3')`, owner, organization.DefaultOrganizationID)
					require.NoError(t, err)
				}
				var id int64
				require.NoError(t, db.QueryRow(`INSERT INTO user_favorites(user_id,tgt_service_id) VALUES($1,$2) RETURNING id`, owner, root).Scan(&id))
				favoriteIDs[id] = owner
			}
			input := []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)}
			if explicit {
				input = append(input, sd3Target(assignment.TargetTypeIntegrationKey, credential.String()), sd3Target(assignment.TargetTypeIntegrationKey, credential.String()))
			}
			if mode == "explicit_before" {
				input[0], input[len(input)-1] = input[len(input)-1], input[0]
			}
			ok, err := sd3App(h).Mutation().DeleteAll(servicePlatformAdminContext(t, h), input)
			require.NoError(t, err)
			require.True(t, ok)
			effects := sd3Effects(t, h, root)
			require.Len(t, effects, 8)
			seen := map[uuid.UUID]bool{}
			for _, f := range effects {
				require.NotEqual(t, uuid.Nil, f.EffectID)
				require.False(t, seen[f.EffectID])
				seen[f.EffectID] = true
				require.Equal(t, h.UUID("org-b"), f.TargetOrganizationID.String())
				switch f.ResourceType {
				case deleteaudit.IntegrationKey:
					require.Contains(t, []uuid.UUID{safe, remaining}, *f.ResourceUUID)
					require.NotEqual(t, credential, *f.ResourceUUID)
					if explicit && *f.ResourceUUID == safe {
						require.Equal(t, "EXPLICIT", f.Provenance)
						require.Equal(t, "explicit_sql", f.DeletionMechanism)
						require.Equal(t, "explicit_target", f.Cause)
					} else {
						require.Equal(t, "CASCADE", f.Provenance)
					}
				case deleteaudit.Alert:
					require.True(t, alertIDs[*f.ResourceNumericID])
					delete(alertIDs, *f.ResourceNumericID)
				case deleteaudit.ServiceFavorite:
					require.Equal(t, favoriteIDs[*f.ResourceNumericID], *f.OwnerUserID)
					switch *f.OwnerUserID {
					case owners[0]:
						require.Equal(t, "known_normal", f.OwnerOrgResolution)
						require.Equal(t, harness.SmokeOrganizationID, f.OwnerOrganizationID.String())
					case owners[1]:
						require.Equal(t, "known_default", f.OwnerOrgResolution)
					default:
						require.Equal(t, "unknown", f.OwnerOrgResolution)
						require.Nil(t, f.OwnerOrganizationID)
					}
				default:
					t.Fatal("unapproved effect type")
				}
			}
			require.Empty(t, alertIDs)
			require.NotContains(t, sd1Rows(t, h), credential.String())
			require.NotContains(t, sd1Rows(t, h), "SD3 synthetic")
			before := sd1Rows(t, h)
			_, err = db.Exec(`DELETE FROM users WHERE id=$1`, owners[1])
			require.NoError(t, err)
			require.Equal(t, before, sd1Rows(t, h))
			// An actual root without children records authoritative complete-empty.
			ok, err = sd3App(h).Mutation().DeleteAll(servicePlatformAdminContext(t, h), []assignment.RawTarget{sd3Target(assignment.TargetTypeService, h.UUID("service-c"))})
			require.NoError(t, err)
			require.True(t, ok)
			require.Empty(t, sd3Effects(t, h, h.UUID("service-c")))
		})
	}
}

func TestServiceCascadePG04MultipleRootsAndPG21UnattachedKey(t *testing.T) {
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	db := h.App().DB()
	root, second := h.UUID("service-b"), uuid.NewString()
	_, err := db.Exec(`INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,'SD3 second')`, second, h.UUID("org-b"), h.UUID("policy-b"))
	require.NoError(t, err)
	_, safe1 := sd3Key(t, h, root)
	_, safe2 := sd3Key(t, h, second)
	unattached, _ := sd3Key(t, h, h.UUID("service-a"))
	ok, err := sd3App(h).Mutation().DeleteAll(servicePlatformAdminContext(t, h), []assignment.RawTarget{sd3Target(assignment.TargetTypeService, second), sd3Target(assignment.TargetTypeIntegrationKey, unattached.String()), sd3Target(assignment.TargetTypeService, root)})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, safe1, *sd3Effects(t, h, root)[0].ResourceUUID)
	require.Equal(t, safe2, *sd3Effects(t, h, second)[0].ResourceUUID)
	require.Equal(t, 2, sd1Count(t, h, "committed"))
	var keyExists bool
	require.NoError(t, db.QueryRow(`SELECT EXISTS(SELECT FROM integration_keys WHERE id=$1)`, unattached).Scan(&keyExists))
	require.False(t, keyExists)
	key, _ := sd3Key(t, h, h.UUID("service-c"))
	before := sd1Rows(t, h)
	ok, err = sd3App(h).Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeIntegrationKey, key.String())})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, before, sd1Rows(t, h), "Key-only does not mint a Service root")
}

func TestServiceCascadePG08SuppressionAndPG21NoActualRoot(t *testing.T) {
	for _, mode := range []string{"root", "child", "reparent", "partial"} {
		t.Run(mode, func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			root := h.UUID("service-b")
			key, _ := sd3Key(t, h, root)
			other, _ := sd3Key(t, h, root)
			body := `RETURN NULL;`
			table := "services"
			if mode == "child" {
				table = "integration_keys"
			}
			if mode == "reparent" {
				body = fmt.Sprintf(`UPDATE integration_keys SET service_id='%s' WHERE id='%s'; RETURN OLD;`, h.UUID("service-a"), other)
			}
			if mode == "partial" {
				body = fmt.Sprintf(`DELETE FROM integration_keys WHERE id='%s'; RETURN NULL;`, other)
			}
			_, err := db.Exec(`CREATE FUNCTION sd3_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ` + body + ` END $$; CREATE TRIGGER sd3_suppress BEFORE DELETE ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION sd3_suppress()`)
			require.NoError(t, err)
			ok, err := sd3App(h).Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root), sd3Target(assignment.TargetTypeIntegrationKey, key.String())})
			if mode == "root" {
				require.NoError(t, err)
				require.True(t, ok)
				var exists bool
				require.NoError(t, db.QueryRow(`SELECT EXISTS(SELECT FROM integration_keys WHERE id=$1)`, key).Scan(&exists))
				require.False(t, exists)
			} else {
				require.Error(t, err)
				require.False(t, ok)
				require.NotContains(t, err.Error(), "sd3_suppress")
			}
			require.Equal(t, 1, serviceManagementCount(t, h, "services", root))
			require.Zero(t, sd1Count(t, h, "committed"))
		})
	}
}

func TestServiceCascadePG20Isolation(t *testing.T) {
	for _, isolation := range []string{"read committed", "repeatable read", "serializable"} {
		t.Run(isolation, func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			var database string
			require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&database))
			cfg, err := pgx.ParseConfig(harness.DBURL(database))
			require.NoError(t, err)
			cfg.RuntimeParams["default_transaction_isolation"] = isolation
			isolated := stdlib.OpenDB(*cfg)
			defer isolated.Close()
			isolated.SetMaxOpenConns(2)
			store, err := service.NewStore(t.Context(), isolated)
			require.NoError(t, err)
			a := graphqlapp.App{DB: isolated, ServiceStore: store}
			ok, err := a.Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeService, h.UUID("service-b"))})
			if isolation == "read committed" {
				require.NoError(t, err)
				require.True(t, ok)
				require.Len(t, sd3Effects(t, h, h.UUID("service-b")), 0)
			} else {
				require.Error(t, err)
				require.False(t, ok)
				require.Equal(t, 1, serviceManagementCount(t, h, "services", h.UUID("service-b")))
				require.Zero(t, sd1Count(t, h, "committed"))
			}
			// CMNR-only retains its accepted isolation behavior. It has no
			// Service child-capture snapshot requirement and no new gate.
			cm := uuid.New()
			_, err = db.Exec(`INSERT INTO user_contact_methods(id,user_id,name,type,value) VALUES($1,$2,'SD3 isolation CM','WEBHOOK','http://localhost/SD3-isolation')`, cm, h.UUID("user-a"))
			require.NoError(t, err)
			cmApp := graphqlapp.App{DB: isolated, CMStore: h.App().ContactMethodStore}
			ok, err = cmApp.Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeContactMethod, cm.String())})
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, 1, cmnrAuditCount(t, h, "success_witness"))
		})
	}
}

// PostgreSQL's own lock graph is the barrier. Timing delays alone are not proof.
func sd3WaitBlocked(t *testing.T, db *sql.DB, pid int) {
	t.Helper()
	require.Eventually(t, func() bool {
		var n int
		err := db.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, pid).Scan(&n)
		return err == nil && n > 0
	}, 5*time.Second, 10*time.Millisecond)
}

func TestServiceCascadePG05RootWaitIncludesCommittedChild(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	root := h.UUID("service-b")
	conn, err := db.Conn(t.Context())
	require.NoError(t, err)
	defer conn.Close()
	tx, err := conn.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	var pid int
	require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
	_, err = tx.Exec(`SELECT id FROM services WHERE id=$1 FOR UPDATE`, root)
	require.NoError(t, err)
	type result struct {
		ok  bool
		err error
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(sd3System(), 15*time.Second)
	defer cancel()
	go func() {
		ok, err := sd3App(h).Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)})
		done <- result{ok, err}
	}()
	sd3WaitBlocked(t, db, pid)
	var alert int64
	require.NoError(t, tx.QueryRow(`INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'SD3 lock-before','sd3-before') RETURNING id`, root).Scan(&alert))
	require.NoError(t, tx.Commit())
	r := <-done
	require.NoError(t, r.err)
	require.True(t, r.ok)
	effects := sd3Effects(t, h, root)
	require.Len(t, effects, 1)
	require.Equal(t, alert, *effects[0].ResourceNumericID)
}

func TestServiceCascadePG06ChildLockWaitRechecksMembership(t *testing.T) {
	for _, typ := range []string{deleteaudit.IntegrationKey, deleteaudit.Alert, deleteaudit.ServiceFavorite} {
		for _, action := range []string{"move", "delete"} {
			t.Run(typ+"/"+action, func(t *testing.T) {
				h := sd1Harness(t)
				db := h.App().DB()
				root := h.UUID("service-b")
				table, parent := "alerts", "service_id"
				var id any
				switch typ {
				case deleteaudit.IntegrationKey:
					credential, _ := sd3Key(t, h, root)
					id = credential
					table = "integration_keys"
				case deleteaudit.Alert:
					id = sd3Alert(t, h, root, "triggered")
				case deleteaudit.ServiceFavorite:
					var n int64
					require.NoError(t, db.QueryRow(`INSERT INTO user_favorites(user_id,tgt_service_id) VALUES($1,$2) RETURNING id`, h.UUID("user-a"), root).Scan(&n))
					id = n
					table, parent = "user_favorites", "tgt_service_id"
				}
				conn, err := db.Conn(t.Context())
				require.NoError(t, err)
				defer conn.Close()
				tx, err := conn.BeginTx(t.Context(), nil)
				require.NoError(t, err)
				defer func() { _ = tx.Rollback() }()
				var pid int
				require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
				_, err = tx.Exec(`SELECT id FROM `+table+` WHERE id=$1 FOR UPDATE`, id)
				require.NoError(t, err)
				ctx, cancel := context.WithTimeout(sd3System(), 15*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() {
					_, err := sd3App(h).Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)})
					done <- err
				}()
				sd3WaitBlocked(t, db, pid)
				if action == "move" {
					_, err = tx.Exec(`UPDATE `+table+` SET `+parent+`=$2 WHERE id=$1`, id, h.UUID("service-a"))
				} else {
					_, err = tx.Exec(`DELETE FROM `+table+` WHERE id=$1`, id)
				}
				require.NoError(t, err)
				require.NoError(t, tx.Commit())
				require.NoError(t, <-done)
				require.Empty(t, sd3Effects(t, h, root))
				if action == "move" {
					var actual string
					require.NoError(t, db.QueryRow(`SELECT `+parent+` FROM `+table+` WHERE id=$1`, id).Scan(&actual))
					require.Equal(t, h.UUID("service-a"), actual)
				} else {
					var exists bool
					require.NoError(t, db.QueryRow(`SELECT EXISTS(SELECT FROM `+table+` WHERE id=$1)`, id).Scan(&exists))
					require.False(t, exists)
				}
			})
		}
	}
}

func TestServiceCascadePG13CountBudget(t *testing.T) {
	for _, count := range []int{deleteaudit.MaxEffects, deleteaudit.MaxEffects + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			root := h.UUID("service-b")
			_, err := db.Exec(`INSERT INTO alerts(service_id,summary,status) SELECT $1,'SD3 capacity','closed' FROM generate_series(1,$2)`, root, count)
			require.NoError(t, err)
			ok, err := sd3App(h).Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)})
			if count == deleteaudit.MaxEffects {
				require.NoError(t, err)
				require.True(t, ok)
				require.Len(t, sd3Effects(t, h, root), count)
			} else {
				require.Error(t, err)
				require.False(t, ok)
				require.Equal(t, 1, serviceManagementCount(t, h, "services", root))
				require.Zero(t, sd1Count(t, h, "committed"))
				var n int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM alerts WHERE service_id=$1`, root).Scan(&n))
				require.Equal(t, count, n)
			}
		})
	}
}

func TestServiceCascadePG18MissingSchemaFailsClosed(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	root := h.UUID("service-b")
	_, _ = sd3Key(t, h, root)
	_, err := db.Exec(`ALTER TABLE integration_keys RENAME COLUMN audit_resource_id TO unavailable_audit_resource_id`)
	require.NoError(t, err)
	ok, err := sd3App(h).Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)})
	require.Error(t, err)
	require.False(t, ok)
	require.Equal(t, 1, serviceManagementCount(t, h, "services", root))
	require.Zero(t, sd1Count(t, h, "committed"))
	require.False(t, strings.Contains(err.Error(), "unavailable_audit_resource_id"))
}
