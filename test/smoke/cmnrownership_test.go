package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/util/sqlutil"
)

func cmnrUser(name string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("cmnr-ownership:"+name)).String()
}

func cmnrHarness(t *testing.T, crossOrg bool, orgRole string) *harness.Harness {
	t.Helper()
	h := harness.NewHarness(t, "", "")
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	db := h.App().DB()
	exec := func(q string, args ...any) {
		t.Helper()
		_, err := db.ExecContext(t.Context(), q, args...)
		require.NoError(t, err)
	}
	orgB := harness.SmokeOrganizationID
	if crossOrg {
		orgB = cmnrUser("org-b")
		exec(`INSERT INTO organizations(id, classification, display_name, canonical_name)
			VALUES ($1, 'NORMAL', 'CMNR B', 'cmnr-ownership.b')`, orgB)
		exec(`INSERT INTO normal_organizations(organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
			VALUES ($1, 'NORMAL', 'cmnr-ownership:b', 'Asia/Shanghai')`, orgB)
	}
	for _, name := range []string{"alice", "bob"} {
		exec(`INSERT INTO users(id, name, email, role) VALUES ($1, $2, '', 'user')`, cmnrUser(name), name)
		org := harness.SmokeOrganizationID
		if name == "bob" {
			org = orgB
		}
		exec(`INSERT INTO user_organization_assignments(user_id, effective_organization_id,
			effective_organization_classification, effective_normal_organization_id, organization_role,
			mapping_outcome, authoritative_evaluated_at, source_config_version, matched_count)
			VALUES ($1, $2, 'NORMAL', $2, $3, 'EXACTLY_ONE', now(), 'cmnr-ownership-test', 1)`, cmnrUser(name), org, orgRole)
	}
	var database, actor, version string
	var migrations int
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT current_database(), current_user, current_setting('server_version')`).Scan(&database, &actor, &version))
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT count(*) FROM gorp_migrations`).Scan(&migrations))
	t.Logf("Task-owned DB=%s role=%s PostgreSQL=%s migrations=%d; Alice=%s Bob=%s orgRole=%s crossOrg=%t", database, actor, version, migrations, cmnrUser("alice"), cmnrUser("bob"), orgRole, crossOrg)
	return h
}

func cmnrHuman(t *testing.T, h *harness.Harness, name string) context.Context {
	t.Helper()
	id, session := cmnrUser(name), uuid.NewString()
	ctx := permission.UserSourceContext(h.Config().Context(t.Context()), id, permission.RoleUser,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session})
	r, err := auth.NewRequester(id, session)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, r)
	c, err := executioncontext.NewHumanExecutionContextConstructor(h.App().OrganizationStore)
	require.NoError(t, err)
	authority, err := c.Construct(ctx)
	require.NoError(t, err)
	return executioncontext.WithExecutionContext(ctx, authority)
}

type cmnrFixture struct {
	cm [4]string // three Alice CMs, one Bob CM
	nr [5]string // one NR per Alice CM, two NRs on Bob's CM
}

func cmnrSeed(t *testing.T, h *harness.Harness) cmnrFixture {
	t.Helper()
	f := cmnrFixture{}
	db := h.App().DB()
	for i := range f.cm {
		f.cm[i] = uuid.NewString()
		owner := cmnrUser("alice")
		if i == 3 {
			owner = cmnrUser("bob")
		}
		dest, err := json.Marshal(map[string]any{"Type": "builtin-smtp-email", "Args": map[string]string{"email_address": f.cm[i] + "@example.invalid"}})
		require.NoError(t, err)
		_, err = db.ExecContext(t.Context(), `INSERT INTO user_contact_methods(id,user_id,name,dest,private,disabled) VALUES($1,$2,'CMNR ownership',$3,true,false)`, f.cm[i], owner, dest)
		require.NoError(t, err)
	}
	for i := range f.nr {
		f.nr[i] = uuid.NewString()
		j, owner, delay := i, cmnrUser("alice"), 0
		if i >= 3 {
			j, owner, delay = 3, cmnrUser("bob"), i-3
		}
		_, err := db.ExecContext(t.Context(), `INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,$4)`, f.nr[i], owner, f.cm[j], delay)
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(), `DELETE FROM user_contact_methods WHERE id=ANY($1::uuid[])`, sqlutil.UUIDArray(f.cm[:]))
		require.NoError(t, err)
	})
	return f
}

// Full persisted row contents plus xmin catch updates as well as deletions.
func cmnrSnapshot(t *testing.T, db gadb.DBTX) map[string]string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT 'CM:'||id::text, (to_jsonb(c)||jsonb_build_object('xmin',xmin::text))::text FROM user_contact_methods c
		UNION ALL SELECT 'NR:'||id::text, (to_jsonb(n)||jsonb_build_object('xmin',xmin::text))::text FROM user_notification_rules n`)
	require.NoError(t, err)
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var id, row string
		require.NoError(t, rows.Scan(&id, &row))
		result[id] = row
	}
	require.NoError(t, rows.Err())
	return result
}

func cmnrSideEffects(t *testing.T, db gadb.DBTX) string {
	t.Helper()
	var result string
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT jsonb_build_object(
		'outgoing',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM outgoing_messages r),
		'verification',(SELECT jsonb_agg(to_jsonb(r) ORDER BY contact_method_id) FROM user_verification_codes r),
		'status',(SELECT jsonb_agg(to_jsonb(r) ORDER BY contact_method_id) FROM alert_status_subscriptions r))::text`).Scan(&result))
	return result
}

func cmnrWithout(before map[string]string, f cmnrFixture, typ string, ids []string) map[string]string {
	want := maps.Clone(before)
	for _, id := range ids {
		delete(want, typ+":"+id)
		if typ != "CM" {
			continue
		}
		for i, cm := range f.cm {
			if cm == id {
				delete(want, "NR:"+f.nr[i])
				if i == 3 {
					delete(want, "NR:"+f.nr[4])
				}
			}
		}
	}
	return want
}

func cmnrDelete(ctx context.Context, h *harness.Harness, typ string, tx *sql.Tx, ids []string) error {
	if typ == "NR" {
		return h.App().NotificationRuleStore.DeleteTx(ctx, tx, ids...)
	}
	if tx != nil {
		return h.App().ContactMethodStore.Delete(ctx, tx, ids...)
	}
	return h.App().ContactMethodStore.Delete(ctx, h.App().DB(), ids...)
}

func TestCMNROwnershipStore(t *testing.T) {
	for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN"} {
		for _, cross := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cross_org_%t", role, cross), func(t *testing.T) {
				h := cmnrHarness(t, cross, role)
				for _, typ := range []string{"CM", "NR"} {
					for _, explicit := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/explicit_tx_%t", typ, explicit), func(t *testing.T) {
							for _, name := range []string{"own_single", "own_multiple", "foreign_only", "mixed", "multiple_own_foreign", "duplicate_own", "missing", "own_missing", "mixed_missing", "empty", "invalid_uuid", "over_limit", "missing_owner", "invalid_owner", "nil_owner", "unauthenticated"} {
								t.Run(name, func(t *testing.T) {
									f := cmnrSeed(t, h)
									ids := f.cm[:]
									if typ == "NR" {
										ids = f.nr[:]
									}
									ctx := cmnrHuman(t, h, "alice")
									var targets []string
									denied, invalid := false, false
									switch name {
									case "own_single":
										targets = ids[:1]
									case "own_multiple":
										targets = ids[:3]
									case "foreign_only":
										targets, denied = ids[3:4], true
									case "mixed":
										targets, denied = []string{ids[0], ids[3]}, true
									case "multiple_own_foreign":
										targets, denied = ids[:4], true
									case "duplicate_own":
										targets = []string{ids[0], ids[0], ids[1]}
									case "missing":
										targets = []string{uuid.NewString()}
									case "own_missing":
										targets = []string{ids[0], uuid.NewString()}
									case "mixed_missing":
										targets, denied = []string{ids[0], ids[3], uuid.NewString()}, true
									case "empty":
										targets = []string{}
									case "invalid_uuid":
										targets, invalid = []string{ids[0], "invalid"}, true
									case "over_limit":
										for range 51 {
											targets = append(targets, ids[0])
										}
										invalid = true
									case "missing_owner", "invalid_owner", "nil_owner":
										owner := ""
										if name == "invalid_owner" {
											owner = "invalid"
										}
										if name == "nil_owner" {
											owner = uuid.Nil.String()
										}
										ctx = permission.UserContext(ctx, owner, permission.RoleUser)
										targets, denied = ids[:1], true
									case "unauthenticated":
										ctx, targets, denied = t.Context(), ids[:1], true
									}
									before, side := cmnrSnapshot(t, h.App().DB()), cmnrSideEffects(t, h.App().DB())
									var tx *sql.Tx
									if explicit {
										var err error
										tx, err = h.App().DB().BeginTx(t.Context(), nil)
										require.NoError(t, err)
										defer func() { _ = tx.Rollback() }()
									}
									err := cmnrDelete(ctx, h, typ, tx, targets)
									if denied {
										assert.Error(t, err)
										assert.True(t, permission.IsPermissionError(err), "%v", err)
									} else if invalid {
										require.Error(t, err)
									} else {
										require.NoError(t, err)
									}
									want := before
									if !denied && !invalid {
										want = cmnrWithout(before, f, typ, targets)
									}
									if explicit {
										assert.Equal(t, want, cmnrSnapshot(t, tx))
										require.Equal(t, before, cmnrSnapshot(t, h.App().DB()), "Store must not commit the caller's transaction")
										// Even after a denied call the caller can commit: no hidden
										// rollback or partial mutation is masked by test cleanup.
										require.NoError(t, tx.Commit())
									}
									require.Equal(t, want, cmnrSnapshot(t, h.App().DB()))
									require.Equal(t, side, cmnrSideEffects(t, h.App().DB()))
								})
							}
						})
					}
				}
			})
		}
	}
}

func TestCMNROwnershipGraphQL(t *testing.T) {
	for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN"} {
		for _, cross := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cross_org_%t", role, cross), func(t *testing.T) {
				h := cmnrHarness(t, cross, role)
				for _, name := range []string{"own_batch", "mixed_cm", "mixed_nr", "nr_before_foreign_cm", "service_before_foreign_cm", "service_before_foreign_nr"} {
					t.Run(name, func(t *testing.T) {
						f := cmnrSeed(t, h)
						before, side := cmnrSnapshot(t, h.App().DB()), cmnrSideEffects(t, h.App().DB())
						var targets []string
						var serviceID, serviceBefore string
						add := func(typ, id string) { targets = append(targets, fmt.Sprintf("{type:%s,id:%q}", typ, id)) }
						want := before
						switch name {
						case "own_batch":
							add("contactMethod", f.cm[0])
							add("notificationRule", f.nr[1])
							add("contactMethod", f.cm[2])
							want = cmnrWithout(cmnrWithout(before, f, "CM", []string{f.cm[0], f.cm[2]}), f, "NR", []string{f.nr[1]})
						case "mixed_cm":
							add("contactMethod", f.cm[0])
							add("contactMethod", f.cm[3])
						case "mixed_nr":
							add("notificationRule", f.nr[0])
							add("notificationRule", f.nr[3])
						case "nr_before_foreign_cm":
							// Deliberately reverse input order. DeleteAll executes NR before CM.
							add("contactMethod", f.cm[3])
							add("notificationRule", f.nr[0])
						case "service_before_foreign_cm", "service_before_foreign_nr":
							policy, service := uuid.NewString(), uuid.NewString()
							serviceID = service
							_, err := h.App().DB().ExecContext(t.Context(), `INSERT INTO escalation_policies(id,name,organization_id) VALUES($1,$2,$3)`, policy, "CMNR "+policy, harness.SmokeOrganizationID)
							require.NoError(t, err)
							_, err = h.App().DB().ExecContext(t.Context(), `INSERT INTO services(id,name,escalation_policy_id,organization_id) VALUES($1,$2,$3,$4)`, service, "CMNR "+service, policy, harness.SmokeOrganizationID)
							require.NoError(t, err)
							require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT (to_jsonb(s)||jsonb_build_object('xmin',xmin::text))::text FROM services s WHERE id=$1`, service).Scan(&serviceBefore))
							if name == "service_before_foreign_cm" {
								add("contactMethod", f.cm[3])
							} else {
								add("notificationRule", f.nr[3])
							}
							add("service", service)
						}
						response := h.GraphQLQueryUserT(t, cmnrUser("alice"), "mutation {deleteAll(input:["+strings.Join(targets, ",")+"])}")
						if name == "own_batch" {
							require.Empty(t, response.Errors)
							require.JSONEq(t, `{"deleteAll":true}`, string(response.Data))
						} else {
							require.NotEmpty(t, response.Errors)
							require.Contains(t, response.Errors[0].Message, "access denied")
						}
						require.Equal(t, want, cmnrSnapshot(t, h.App().DB()))
						require.Equal(t, side, cmnrSideEffects(t, h.App().DB()))
						if serviceID != "" {
							var actual string
							require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT (to_jsonb(s)||jsonb_build_object('xmin',xmin::text))::text FROM services s WHERE id=$1`, serviceID).Scan(&actual))
							require.Equal(t, serviceBefore, actual, "earlier authorized Service deletion must roll back")
						}
					})
				}
			})
		}
	}
}

func TestCMNROwnershipCascade(t *testing.T) {
	h := cmnrHarness(t, true, "ORG_MEMBER")
	f := cmnrSeed(t, h)
	before, side := cmnrSnapshot(t, h.App().DB()), cmnrSideEffects(t, h.App().DB())
	err := cmnrDelete(cmnrHuman(t, h, "alice"), h, "CM", nil, []string{f.cm[0], f.cm[3]})
	require.True(t, permission.IsPermissionError(err), "%v", err)
	require.Equal(t, before, cmnrSnapshot(t, h.App().DB()), "Alice CM, Bob CM and both dependent Bob NRs must remain byte-identical")
	require.NoError(t, cmnrDelete(cmnrHuman(t, h, "bob"), h, "CM", nil, []string{f.cm[3]}))
	require.Equal(t, cmnrWithout(before, f, "CM", []string{f.cm[3]}), cmnrSnapshot(t, h.App().DB()), "Bob's authorized deletion must cascade to both Bob NRs, preserving Alice")
	require.Equal(t, side, cmnrSideEffects(t, h.App().DB()))
}

func TestCMNROwnershipLegacyCompatibility(t *testing.T) {
	h := cmnrHarness(t, true, "ORG_MEMBER")
	for _, typ := range []string{"CM", "NR"} {
		for _, actor := range []string{"admin", "system"} {
			t.Run(typ+"/"+actor, func(t *testing.T) {
				f := cmnrSeed(t, h)
				ids := f.cm[:]
				if typ == "NR" {
					ids = f.nr[:]
				}
				before := cmnrSnapshot(t, h.App().DB())
				deleteTargets := []string{ids[0], ids[3]}
				if actor == "admin" {
					require.NoError(t, cmnrDelete(permission.UserContext(t.Context(), cmnrUser("alice"), permission.RoleAdmin), h, typ, nil, deleteTargets))
				} else {
					permission.SudoContext(t.Context(), func(ctx context.Context) { require.NoError(t, cmnrDelete(ctx, h, typ, nil, deleteTargets)) })
				}
				require.Equal(t, cmnrWithout(before, f, typ, deleteTargets), cmnrSnapshot(t, h.App().DB()))
			})
		}
	}
}

func TestCMNROwnershipConcurrent(t *testing.T) {
	h := cmnrHarness(t, true, "ORG_MEMBER")
	for _, typ := range []string{"CM", "NR"} {
		for _, operation := range []string{"delete", "own_delete", "metadata_update"} {
			t.Run(typ+"/"+operation, func(t *testing.T) {
				f := cmnrSeed(t, h)
				ids := f.cm[:]
				if typ == "NR" {
					ids = f.nr[:]
				}
				ctx, cancel := context.WithTimeout(cmnrHuman(t, h, "alice"), 10*time.Second)
				defer cancel()
				db := h.App().DB()
				blocker, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = blocker.Rollback() }()
				var blockerPID int
				require.NoError(t, blocker.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID))
				table := "user_contact_methods"
				field := "name='CMNR concurrently updated'"
				if typ == "NR" {
					table, field = "user_notification_rules", "delay_minutes=7"
				}
				_, err = blocker.ExecContext(ctx, "SELECT id FROM "+table+" WHERE id=$1 FOR UPDATE", ids[0])
				require.NoError(t, err)
				before, side := cmnrSnapshot(t, db), cmnrSideEffects(t, db)
				result := make(chan error, 1)
				targets := []string{ids[0], ids[3]}
				if operation == "own_delete" {
					targets = ids[:2]
				}
				go func() { result <- cmnrDelete(ctx, h, typ, nil, targets) }()
				// Observe an actual PostgreSQL lock wait on this exact blocker,
				// rather than treating simultaneous goroutine starts as overlap.
				waited := false
				deadline := time.Now().Add(3 * time.Second)
				for time.Now().Before(deadline) {
					var count int
					err = db.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, blockerPID).Scan(&count)
					if err != nil || count > 0 {
						waited = count > 0
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				// Always release and join the worker before an assertion can exit.
				if operation == "delete" || operation == "own_delete" {
					err = cmnrDelete(ctx, h, typ, blocker, ids[:1])
				} else {
					_, err = blocker.ExecContext(ctx, "UPDATE "+table+" SET "+field+" WHERE id=$1", ids[0])
				}
				commitErr := blocker.Commit()
				workerErr := <-result
				require.NoError(t, err)
				require.NoError(t, commitErr)
				require.True(t, waited, "must observe real database blocking")
				if operation == "own_delete" {
					require.NoError(t, workerErr)
				} else {
					require.True(t, permission.IsPermissionError(workerErr), "%v", workerErr)
				}
				want := maps.Clone(before)
				if operation == "own_delete" {
					want = cmnrWithout(before, f, typ, ids[:2])
				} else if operation == "delete" {
					want = cmnrWithout(before, f, typ, ids[:1])
				} else {
					// The one deliberate authorized concurrent metadata change is
					// the only permitted difference; all other contents remain exact.
					var row string
					require.NoError(t, db.QueryRowContext(ctx, "SELECT (to_jsonb(r)||jsonb_build_object('xmin',xmin::text))::text FROM "+table+" r WHERE id=$1", ids[0]).Scan(&row))
					require.NotEqual(t, before[typ+":"+ids[0]], row)
					want[typ+":"+ids[0]] = row
				}
				require.Equal(t, want, cmnrSnapshot(t, db))
				require.Equal(t, side, cmnrSideEffects(t, db))
			})
		}
	}
}
