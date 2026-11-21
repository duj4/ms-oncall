package smoke

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
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
			if explicit {
				before := serviceManagementSnapshot(t, h)
				ok, err := sd3App(h).Mutation().DeleteAll(sd3System(), input, nil)
				var safety *ds.DeletionSafetyError
				require.ErrorAs(t, err, &safety)
				require.Equal(t, ds.DeletionUnavailable, safety.Code)
				require.False(t, ok)
				require.Equal(t, before, serviceManagementSnapshot(t, h))
				require.Zero(t, sd1Count(t, h, "committed"))
				require.Zero(t, sd4Count(t, h))
				return // This mixed explicit provenance is outside the executable profiles.
			}
			// The historical unknown favorite owner is not a valid scoped fact.
			before := serviceManagementSnapshot(t, h)
			_, previewErr := smokeDeletionPreview(t, h, sd3System(), input)
			smokeDeletionCode(t, previewErr, ds.DeletionUnavailable)
			ok, err := sd3App(h).Mutation().DeleteAll(sd3System(), input, nil)
			require.Error(t, err)
			require.False(t, ok)
			require.Equal(t, before, serviceManagementSnapshot(t, h))
			require.Zero(t, sd1Count(t, h, "committed"))
			sd8Assign(t, h, owners[2].String(), harness.SmokeOrganizationID)
			before = serviceManagementSnapshot(t, h)
			// Active and triggered Alerts are BLOCK, even after owner repair.
			preview, err := smokeDeletionPreview(t, h, sd3System(), input)
			require.NoError(t, err)
			require.True(t, preview.Complete)
			require.False(t, preview.CanProceed)
			ok, err = sd3App(h).Mutation().DeleteAll(sd3System(), input, nil)
			smokeDeletionCode(t, err, ds.DeletionBlocked)
			require.False(t, ok)
			require.Equal(t, before, serviceManagementSnapshot(t, h))
			require.Zero(t, sd1Count(t, h, "committed"))
			// Closing the two Alerts is a separate fixture transition. Keep all
			// three rows and the original eight B2 effects on the legal path.
			sd8Exec(t, h, `UPDATE alerts SET status='closed',dedup_key=NULL WHERE service_id=$1 AND status<>'closed'`, root)
			ok, err = smokeDeleteAll(t, h, sd3App(h), sd3System(), input)
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
					require.Equal(t, "CASCADE", f.Provenance)
					require.Equal(t, "fk_cascade", f.DeletionMechanism)
					require.Equal(t, "service_delete", f.Cause)
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
						require.Equal(t, "known_normal", f.OwnerOrgResolution)
						require.Equal(t, harness.SmokeOrganizationID, f.OwnerOrganizationID.String())
					}
				default:
					t.Fatal("unapproved effect type")
				}
			}
			require.Empty(t, alertIDs)
			require.NotContains(t, sd1Rows(t, h), credential.String())
			require.NotContains(t, sd1Rows(t, h), "SD3 synthetic")
			beforeAudit := sd1Rows(t, h)
			_, err = db.Exec(`DELETE FROM users WHERE id=$1`, owners[1])
			require.NoError(t, err)
			require.Equal(t, beforeAudit, sd1Rows(t, h))
			// An actual root without children records authoritative complete-empty.
			ok, err = smokeDeleteAll(t, h, sd3App(h), sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeService, h.UUID("service-c"))})
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
	mixed := []assignment.RawTarget{sd3Target(assignment.TargetTypeService, second), sd3Target(assignment.TargetTypeIntegrationKey, unattached.String()), sd3Target(assignment.TargetTypeService, root)}
	beforeMixed := serviceManagementSnapshot(t, h)
	ok, err := sd3App(h).Mutation().DeleteAll(servicePlatformAdminContext(t, h), mixed, nil)
	smokeDeletionCode(t, err, ds.DeletionUnavailable)
	require.False(t, ok)
	require.Equal(t, beforeMixed, serviceManagementSnapshot(t, h))
	require.Zero(t, sd1Count(t, h, "committed"))
	require.Zero(t, sd4Count(t, h))
	// Two Service roots remain a legal homogeneous batch. The unattached
	// explicit Key is a separate request and must not become a Service effect.
	ok, err = smokeDeleteAll(t, h, sd3App(h), sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeService, second), sd3Target(assignment.TargetTypeService, root)})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, safe1, *sd3Effects(t, h, root)[0].ResourceUUID)
	require.Equal(t, safe2, *sd3Effects(t, h, second)[0].ResourceUUID)
	require.Equal(t, 2, sd1Count(t, h, "committed"))
	var keyExists bool
	require.NoError(t, db.QueryRow(`SELECT EXISTS(SELECT FROM integration_keys WHERE id=$1)`, unattached).Scan(&keyExists))
	require.True(t, keyExists)
	ok, err = smokeDeleteAll(t, h, sd3App(h), sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeIntegrationKey, unattached.String())})
	require.NoError(t, err)
	require.True(t, ok)
	require.Zero(t, serviceManagementCount(t, h, "integration_keys", unattached.String()))
	require.Equal(t, 1, sd4Count(t, h))
	key, _ := sd3Key(t, h, h.UUID("service-c"))
	before := sd1Rows(t, h)
	ok, err = smokeDeleteAll(t, h, sd3App(h), sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeIntegrationKey, key.String())})
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
			// FAULT COVERAGE RESTORATION: keep every original real SQL fault,
			// observe it with a nontransactional sequence on a legal Service root.
			input := []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)}
			confirmation := smokePlanConfirmation(t, h, sd3System(), input)
			_, err := db.Exec(`CREATE SEQUENCE sd3_suppress_hits; CREATE FUNCTION sd3_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('sd3_suppress_hits'); ` + body + ` END $$; CREATE TRIGGER sd3_suppress BEFORE DELETE ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION sd3_suppress()`)
			require.NoError(t, err)
			smokeContract4Reject(t, h, sd3App(h), sd3System(), append(input, sd3Target(assignment.TargetTypeIntegrationKey, key.String())), nil, ds.DeletionUnavailable)
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM sd3_suppress_hits WHERE is_called`))
			before, audits := serviceManagementSnapshot(t, h), smokeContract4SuccessState(t, h)
			ok, err := sd3App(h).Mutation().DeleteAll(sd3System(), input, confirmation)
			if mode == "root" {
				require.NoError(t, err)
				require.True(t, ok)
			} else {
				require.Error(t, err)
				require.False(t, ok)
				require.NotContains(t, err.Error(), "sd3_suppress")
			}
			require.Positive(t, sd8Scalar(t, h, `SELECT last_value FROM sd3_suppress_hits WHERE is_called`), "real original DELETE fault reached")
			require.Equal(t, before, serviceManagementSnapshot(t, h))
			require.Equal(t, audits, smokeContract4SuccessState(t, h))
			require.Equal(t, 1, serviceManagementCount(t, h, "services", root))
			require.Zero(t, sd1Count(t, h, "committed"))
			t.Logf("FAULT COVERAGE RESTORATION: real %s trigger reached, all business identities and successful Audits preserved; mixed explicit-Key semantics NOT REACHABLE", mode)

		})
	}
}

func TestServiceCascadePG20Isolation(t *testing.T) {
	for _, isolation := range []string{"read committed", "repeatable read", "serializable"} {
		t.Run(isolation, func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			isolated := sd5ExternalDB(t, h, isolation)
			var actual string
			require.NoError(t, isolated.QueryRow(`SHOW transaction_isolation`).Scan(&actual))
			require.Equal(t, isolation, actual)
			store, err := service.NewStore(t.Context(), isolated)
			require.NoError(t, err)
			a := graphqlapp.App{DB: isolated, ServiceStore: store}
			root := h.UUID("service-b")
			_, safe := sd3Key(t, h, root)
			closed := sd3Alert(t, h, root, "closed")
			input := []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)}
			confirmation, err := smokeDeletionConfirmation(t, h, sd3System(), input)
			require.NoError(t, err)
			if isolation != "read committed" {
				smokeContract4IsolationReject(t, h, &a, input, confirmation)
			} else {
				ok, err := a.Mutation().DeleteAll(sd3System(), input, confirmation)
				require.NoError(t, err)
				require.True(t, ok)
				effects := sd3Effects(t, h, root)
				require.Len(t, effects, 2)
				for _, f := range effects {
					switch f.ResourceType {
					case deleteaudit.IntegrationKey:
						require.Equal(t, safe, *f.ResourceUUID)
					case deleteaudit.Alert:
						require.Equal(t, closed, *f.ResourceNumericID)
					default:
						t.Fatal("unapproved Service effect")
					}
				}
				require.Zero(t, serviceManagementCount(t, h, "services", root))
				require.Equal(t, 1, sd1Count(t, h, "committed"))
			}
			// Preserve the old CM-only branch under the same global isolation gate.
			cm := uuid.New()
			sd8Exec(t, h, `INSERT INTO user_contact_methods(id,user_id,name,type,value) VALUES($1,$2,'SD3 isolation CM','WEBHOOK','http://localhost/SD3-isolation')`, cm, h.UUID("user-a"))
			cmApp := graphqlapp.App{DB: isolated, CMStore: h.App().ContactMethodStore}
			cmInput := []assignment.RawTarget{sd3Target(assignment.TargetTypeContactMethod, cm.String())}
			confirmation, err = smokeDeletionConfirmation(t, h, sd3System(), cmInput)
			require.NoError(t, err)
			if isolation != "read committed" {
				smokeContract4IsolationReject(t, h, &cmApp, cmInput, confirmation)
				require.Zero(t, cmnrAuditCount(t, h, "success_witness"))
			} else {
				ok, err := cmApp.Mutation().DeleteAll(sd3System(), cmInput, confirmation)
				require.NoError(t, err)
				require.True(t, ok)
				require.Equal(t, 1, cmnrAuditCount(t, h, "success_witness"))
			}
			require.NoError(t, db.Ping())
			t.Log("actual PostgreSQL isolation checked; legacy RR/Serializable success NOT REACHABLE, full business and successful Audit snapshots retained on rejection")
		})
	}
}

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
	input := []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)}
	confirmation, err := smokeDeletionConfirmation(t, h, sd3System(), input)
	require.NoError(t, err)
	tx, err := sd5ExternalDB(t, h, "").BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT id FROM services WHERE id=$1 FOR UPDATE`, root)
	require.NoError(t, err)
	smokeContract4LockPID(t, h, tx)
	smokeContract4Reject(t, h, sd3App(h), sd3System(), input, confirmation, ds.DeletionUnavailable)
	var alert int64
	require.NoError(t, tx.QueryRow(`INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'SD3 lock-before','sd3-before') RETURNING id`, root).Scan(&alert))
	require.NoError(t, tx.Commit())
	// Preserve the original triggered Alert and its parent as a genuine BLOCK.
	smokeContract4Blocked(t, h, sd3App(h), input)
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM alerts WHERE id=$1 AND service_id=$2 AND status='triggered'`, alert, root))
	// Independent legal root: a committed closed child invalidates the old
	// confirmation, then a fresh Preview captures its complete B2 receipt.
	legal := smokeContract4Service(t, h, false)
	legalInput := []assignment.RawTarget{sd3Target(assignment.TargetTypeService, legal)}
	stale := smokePlanConfirmation(t, h, sd3System(), legalInput)
	writer, err := sd5ExternalDB(t, h, "").BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = writer.Rollback() }()
	_, err = writer.Exec(`SELECT id FROM services WHERE id=$1 FOR UPDATE`, legal)
	require.NoError(t, err)
	smokeContract4LockPID(t, h, writer)
	var closed int64
	require.NoError(t, writer.QueryRow(`INSERT INTO alerts(service_id,summary,status) VALUES($1,'SD3 legal committed child','closed') RETURNING id`, legal).Scan(&closed))
	require.NoError(t, writer.Commit())
	smokeContract4Reject(t, h, sd3App(h), sd3System(), legalInput, stale, ds.DeletionDependencyChanged)
	smokeContract4Gate(t, h, sd3App(h), sd3System(), legalInput, "services", false, func(ctx context.Context, pid int) { require.Positive(t, pid) })
	effects := sd3Effects(t, h, legal)
	require.Len(t, effects, 1)
	require.Equal(t, closed, *effects[0].ResourceNumericID)
	require.Zero(t, serviceManagementCount(t, h, "services", legal))
	require.Equal(t, 1, serviceManagementCount(t, h, "services", root))
	require.Equal(t, 1, sd1Count(t, h, "committed"))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM alerts WHERE id=$1 AND service_id=$2 AND status='triggered'`, alert, root))
	require.NoError(t, db.Ping())
	t.Log("old Root lock wait NOT REACHABLE; original triggered relation preserved, independent RC writer/changed-version/DELETE barrier and closed-child B2 receipt verified")
}

func TestServiceCascadePG06ChildLockWaitRechecksMembership(t *testing.T) {
	for _, typ := range []string{deleteaudit.IntegrationKey, deleteaudit.Alert, deleteaudit.ServiceFavorite} {
		for _, action := range []string{"move", "delete"} {
			t.Run(typ+"/"+action, func(t *testing.T) {
				h := sd1Harness(t)
				db := h.App().DB()
				root := h.UUID("service-b")
				var blocked int64
				if typ == deleteaudit.Alert {
					blocked = sd3Alert(t, h, root, "triggered")
					smokeContract4Blocked(t, h, sd3App(h), []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)})
					root = smokeContract4Service(t, h, false)
				}
				table, parent := "alerts", "service_id"
				var id any
				switch typ {
				case deleteaudit.IntegrationKey:
					credential, _ := sd3Key(t, h, root)
					id = credential
					table = "integration_keys"
				case deleteaudit.Alert:
					id = sd3Alert(t, h, root, "closed")
				case deleteaudit.ServiceFavorite:
					var n int64
					require.NoError(t, db.QueryRow(`INSERT INTO user_favorites(user_id,tgt_service_id) VALUES($1,$2) RETURNING id`, h.UUID("user-a"), root).Scan(&n))
					id = n
					table, parent = "user_favorites", "tgt_service_id"
				}
				input := []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)}
				confirmation := smokePlanConfirmation(t, h, sd3System(), input)
				tx, err := sd5ExternalDB(t, h, "").BeginTx(t.Context(), nil)
				require.NoError(t, err)
				defer func() { _ = tx.Rollback() }()
				_, err = tx.Exec(`SELECT id FROM `+table+` WHERE id=$1 FOR UPDATE`, id)
				require.NoError(t, err)
				smokeContract4LockPID(t, h, tx)
				smokeContract4Reject(t, h, sd3App(h), sd3System(), input, confirmation, ds.DeletionUnavailable)
				if action == "move" {
					_, err = tx.Exec(`UPDATE `+table+` SET `+parent+`=$2 WHERE id=$1`, id, h.UUID("service-a"))
				} else {
					_, err = tx.Exec(`DELETE FROM `+table+` WHERE id=$1`, id)
				}
				require.NoError(t, err)
				require.NoError(t, tx.Commit())
				smokeContract4Reject(t, h, sd3App(h), sd3System(), input, confirmation, ds.DeletionDependencyChanged)
				ok, err := smokeDeleteAll(t, h, sd3App(h), sd3System(), input)
				require.NoError(t, err)
				require.True(t, ok)
				require.Empty(t, sd3Effects(t, h, root))
				require.Equal(t, 1, sd1Count(t, h, "committed"))
				require.Zero(t, serviceManagementCount(t, h, "services", root))
				if action == "move" {
					var actual string
					require.NoError(t, db.QueryRow(`SELECT `+parent+` FROM `+table+` WHERE id=$1`, id).Scan(&actual))
					require.Equal(t, h.UUID("service-a"), actual)
				} else {
					require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM `+table+` WHERE id=$1`, id))
				}
				if blocked != 0 {
					require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM alerts WHERE id=$1 AND service_id=$2 AND status='triggered'`, blocked, h.UUID("service-b")))
					require.Equal(t, 1, serviceManagementCount(t, h, "services", h.UUID("service-b")))
				}
				t.Log("legacy child wait NOT REACHABLE; real row lock refused NOWAIT, writer move/delete committed, stale version refused, fresh B2 membership excludes only the committed external change")
			})
		}
	}
}

func TestServiceCascadePG13CountBudget(t *testing.T) {
	// Preserve both historical Audit-capacity inputs. They now exceed the
	// earlier Preview budget; never pretend the 16384-effect success is legal.
	for _, count := range []int{4096, 9999, 10000, deleteaudit.MaxEffects, deleteaudit.MaxEffects + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			root := h.UUID("service-b")
			_, err := db.Exec(`INSERT INTO alerts(service_id,summary,status) SELECT $1,'SD3 capacity','closed' FROM generate_series(1,$2)`, root, count)
			require.NoError(t, err)
			input := []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)}
			preview, previewErr := smokeDeletionPreview(t, h, sd3System(), input)
			if count >= 10000 {
				smokeDeletionCode(t, previewErr, ds.DeletionPreviewLimitExceeded)
				require.Nil(t, preview)
				ok, mutationErr := sd3App(h).Mutation().DeleteAll(sd3System(), input, nil)
				require.Error(t, mutationErr)
				require.False(t, ok)
			} else {
				require.NoError(t, previewErr)
				require.True(t, preview.Complete)
				require.True(t, preview.CanProceed)
				confirmation := smokePlanConfirmation(t, h, sd3System(), input)
				ok, mutationErr := sd3App(h).Mutation().DeleteAll(sd3System(), input, confirmation)
				if count == 4096 {
					require.NoError(t, mutationErr)
					require.True(t, ok)
					require.Len(t, sd3Effects(t, h, root), count)
					require.Zero(t, serviceManagementCount(t, h, "services", root))
					require.Equal(t, 1, sd1Count(t, h, "committed"))
					return
				}
				// Closure stabilization also charges retained parent/Step rows.
				// A complete Preview is not a promise of mutation capacity.
				require.Error(t, mutationErr)
				require.False(t, ok)
			}
			require.Equal(t, 1, serviceManagementCount(t, h, "services", root))
			require.Zero(t, sd1Count(t, h, "committed"))
			var n int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM alerts WHERE service_id=$1`, root).Scan(&n))
			require.Equal(t, count, n, "every original capacity row remains after refusal")
		})
	}
}

func TestServiceCascadePG18MissingSchemaFailsClosed(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	root := h.UUID("service-b")
	_, safe := sd3Key(t, h, root)
	sd3Alert(t, h, root, "closed")
	input := []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)}
	before, auditBefore := serviceManagementSnapshot(t, h), safetySmokeSuccessState(t, h)
	// Preserve the original missing-column condition as an early refusal only.
	// This database belongs exclusively to this Harness on the private instance.
	var name string
	require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&name))
	require.True(t, strings.HasPrefix(name, "smoketest_"))
	sd8Exec(t, h, `ALTER TABLE integration_keys RENAME COLUMN audit_resource_id TO unavailable_audit_resource_id`)
	restored := false
	defer func() {
		if !restored {
			sd8Exec(t, h, `ALTER TABLE integration_keys RENAME COLUMN unavailable_audit_resource_id TO audit_resource_id`)
		}
	}()
	_, err := smokeDeletionPreview(t, h, sd3System(), input)
	smokeDeletionCode(t, err, ds.DeletionUnavailable)
	ok, err := sd3App(h).Mutation().DeleteAll(sd3System(), input, nil)
	require.Error(t, err)
	require.False(t, ok)
	require.Equal(t, auditBefore, safetySmokeSuccessState(t, h))
	sd8Exec(t, h, `ALTER TABLE integration_keys RENAME COLUMN unavailable_audit_resource_id TO audit_resource_id`)
	restored = true
	require.Equal(t, before, serviceManagementSnapshot(t, h))
	// Obtain the real confirmation while the schema is intact. Rename the SAME
	// required column inside the business transaction at its actual Audit capture
	// SELECT, after Guard certification. PostgreSQL performs and rolls back DDL.
	confirmation, err := smokeDeletionConfirmation(t, h, sd3System(), input)
	require.NoError(t, err)
	connector, err := sd8PGConnector(harness.DBURL(name))
	require.NoError(t, err)
	controlled := sql.OpenDB(connector)
	defer controlled.Close()
	app := sd3App(h)
	app.DB = controlled
	sd8Exec(t, h, `CREATE SEQUENCE safety_schema_hits`)
	var hits atomic.Int64
	codes := make(chan string, 1)
	connector.queryHook = func(ctx context.Context, c driver.Conn, q string, args []driver.NamedValue) (driver.Rows, error, bool) {
		if q != `SELECT audit_resource_id FROM integration_keys WHERE service_id=ANY($1::uuid[]) ORDER BY audit_resource_id FOR UPDATE` {
			return nil, nil, false
		}
		hits.Add(1)
		_, e := c.(driver.ExecerContext).ExecContext(ctx, `SELECT nextval('safety_schema_hits')`, nil)
		if e == nil {
			_, e = c.(driver.ExecerContext).ExecContext(ctx, `ALTER TABLE integration_keys RENAME COLUMN audit_resource_id TO unavailable_audit_resource_id`, nil)
		}
		if e != nil {
			return nil, e, true
		}
		rows, e := c.(driver.QueryerContext).QueryContext(ctx, q, args)
		var pg *pgconn.PgError
		if errors.As(e, &pg) {
			codes <- pg.Code
		}
		return rows, e, true
	}
	ok, err = app.Mutation().DeleteAll(sd3System(), input, confirmation)
	require.Error(t, err)
	require.False(t, ok)
	require.EqualValues(t, 1, hits.Load())
	select {
	case code := <-codes:
		require.Equal(t, "42703", code)
	default:
		t.Fatal("native missing-column error was not reached")
	}
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT last_value FROM safety_schema_hits WHERE is_called`))
	require.Equal(t, before, serviceManagementSnapshot(t, h))
	require.Equal(t, auditBefore, safetySmokeSuccessState(t, h))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM integration_keys WHERE audit_resource_id=$1`, safe))
	require.Equal(t, 1, serviceManagementCount(t, h, "services", root))
	require.Zero(t, sd1Count(t, h, "committed"))
	require.NotContains(t, err.Error(), "audit_resource_id")
	require.NotContains(t, sd1Rows(t, h), "unavailable_audit_resource_id")
	// The same fixture remains executable after transactional schema restoration.
	ok, err = sd3App(h).Mutation().DeleteAll(sd3System(), input, confirmation)
	require.NoError(t, err)
	require.True(t, ok)
	require.Len(t, sd3Effects(t, h, root), 2)
	t.Log("original absent column: Preview refusal; legal Audit capture hit=1 native SQLSTATE=42703; DDL/business/Audit rolled back; unchanged confirmation subsequently committed complete cascade")
}
