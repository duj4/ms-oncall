package smoke

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/user/notificationrule"
)

// Store tests use the canonical constructor; the GraphQL tests below also
// exercise real signed Session authentication. These contexts alone are not
// evidence of an externally exploitable legacy RoleAdmin shortcut.
func cmnrPlatformHarness(t *testing.T, homeRole string) *harness.Harness {
	t.Helper()
	h := cmnrHarness(t, true, homeRole)
	h.GraphQLToken(harness.DefaultGraphQLAdminUserID)
	_, err := h.App().DB().ExecContext(t.Context(), `UPDATE user_organization_assignments SET organization_role=$2 WHERE user_id=$1`, harness.DefaultGraphQLAdminUserID, homeRole)
	require.NoError(t, err)
	return h
}

func cmnrPlatformHuman(t *testing.T, h *harness.Harness, user string) context.Context {
	t.Helper()
	var role permission.Role
	require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT role FROM users WHERE id=$1`, user).Scan(&role))
	h.GraphQLToken(user)
	var session string
	require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT id FROM auth_user_sessions WHERE user_id=$1 ORDER BY id LIMIT 1`, user).Scan(&session))
	ctx := permission.UserSourceContext(h.Config().Context(t.Context()), user, role, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session})
	r, err := auth.NewRequester(user, session)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, r)
	c, err := executioncontext.NewHumanExecutionContextConstructor(h.App().OrganizationStore)
	require.NoError(t, err)
	value, err := c.Construct(ctx)
	require.NoError(t, err)
	require.Equal(t, user, value.ActualActorID())
	require.Equal(t, user, permission.UserID(ctx))
	require.Equal(t, executioncontext.AuthorityModeOrganizationScoped, value.AuthorityMode())
	return executioncontext.WithExecutionContext(ctx, value)
}

func cmnrRestrictBob(t *testing.T, h *harness.Harness, multiple bool) {
	t.Helper()
	count, outcome := 0, "ZERO"
	if multiple {
		count, outcome = 2, "MULTIPLE"
	}
	_, err := h.App().DB().ExecContext(t.Context(), `UPDATE user_organization_assignments
		SET effective_organization_id=$2,effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,
		organization_role='NONE',mapping_outcome=$3,matched_count=$4 WHERE user_id=$1`, cmnrUser("bob"), organization.DefaultOrganizationID, outcome, count)
	require.NoError(t, err)
}

func TestCMNRPlatformAdminStore(t *testing.T) {
	for _, homeRole := range []string{"ORG_MEMBER", "ORG_ADMIN"} {
		t.Run(homeRole, func(t *testing.T) {
			h := cmnrPlatformHarness(t, homeRole)
			for _, typ := range []string{"CM", "NR"} {
				for _, explicit := range []bool{false, true} {
					for _, name := range []string{"multi_org", "duplicates_missing", "empty", "invalid_uuid", "over_limit", "default_target", "multiple_target", "missing_assignment"} {
						t.Run(fmt.Sprintf("%s/tx_%t/%s", typ, explicit, name), func(t *testing.T) {
							f := cmnrSeed(t, h)
							// Restore the task fixture after an invalid-assignment case.
							t.Cleanup(func() {
								_, err := h.App().DB().ExecContext(context.Background(), `DELETE FROM user_organization_assignments WHERE user_id=$1`, cmnrUser("bob"))
								require.NoError(t, err)
								_, err = h.App().DB().ExecContext(context.Background(), `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count)
									VALUES($1,$2,'NORMAL',$2,$3,'EXACTLY_ONE',now(),'s0b-fixture',1)`, cmnrUser("bob"), cmnrUser("org-b"), homeRole)
								require.NoError(t, err)
							})
							ctx := cmnrPlatformHuman(t, h, harness.DefaultGraphQLAdminUserID)
							ids := f.cm[:]
							if typ == "NR" {
								ids = f.nr[:]
							}
							targets := []string{ids[0], ids[3]}
							denied := false
							switch name {
							case "duplicates_missing":
								targets = []string{ids[0], ids[3], ids[0], uuid.NewString()}
							case "empty":
								targets = nil
							case "invalid_uuid":
								targets, denied = []string{ids[0], "invalid"}, true
							case "over_limit":
								targets, denied = nil, true
								for range 51 {
									targets = append(targets, ids[0])
								}
							case "default_target", "multiple_target":
								cmnrRestrictBob(t, h, name == "multiple_target")
								denied = true
							case "missing_assignment":
								_, err := h.App().DB().ExecContext(t.Context(), `DELETE FROM user_organization_assignments WHERE user_id=$1`, cmnrUser("bob"))
								require.NoError(t, err)
								denied = true
							}
							before, side := cmnrSnapshot(t, h.App().DB()), cmnrSideEffects(t, h.App().DB())
							var tx *sql.Tx
							var err error
							if explicit {
								tx, err = h.App().DB().BeginTx(ctx, nil)
								require.NoError(t, err)
								defer func() { _ = tx.Rollback() }()
							}
							err = cmnrDelete(ctx, h, typ, tx, targets)
							if denied {
								require.Error(t, err)
							} else {
								require.NoError(t, err)
							}
							if explicit {
								require.Equal(t, before, cmnrSnapshot(t, h.App().DB()), "Store must not commit caller transaction")
								var probe int
								require.NoError(t, tx.QueryRowContext(ctx, `SELECT 1`).Scan(&probe), "authorization rejection must leave caller transaction usable")
								if denied {
									require.NoError(t, tx.Rollback())
								} else {
									require.NoError(t, tx.Commit())
								}
							}
							want := before
							if !denied {
								want = cmnrWithout(before, f, typ, targets)
							}
							require.Equal(t, want, cmnrSnapshot(t, h.App().DB()))
							require.Equal(t, side, cmnrSideEffects(t, h.App().DB()))
						})
					}
				}
			}
		})
	}
}

func TestCMNRPlatformAdminCreate(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		for _, name := range []string{"owner", "platform_cross_org", "orgadmin_nonowner", "orgadmin_sameorg_nonowner", "synthetic_admin", "missing_user", "missing_cm", "wrong_cm_user", "default_target", "multiple_target", "missing_assignment", "system_without_assignment"} {
			t.Run(fmt.Sprintf("tx_%t/%s", explicit, name), func(t *testing.T) {
				h := cmnrPlatformHarness(t, "ORG_ADMIN")
				f := cmnrSeed(t, h)
				ctx := cmnrPlatformHuman(t, h, harness.DefaultGraphQLAdminUserID)
				n := &notificationrule.NotificationRule{UserID: cmnrUser("bob"), ContactMethodID: uuid.MustParse(f.cm[3]), DelayMinutes: 9}
				denied := false
				switch name {
				case "owner":
					ctx = cmnrHuman(t, h, "bob")
				case "orgadmin_nonowner":
					ctx, denied = cmnrHuman(t, h, "alice"), true
				case "orgadmin_sameorg_nonowner":
					_, err := h.App().DB().ExecContext(t.Context(), `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, cmnrUser("bob"), harness.SmokeOrganizationID)
					require.NoError(t, err)
					ctx, denied = cmnrHuman(t, h, "alice"), true
				case "synthetic_admin":
					ctx, denied = permission.UserContext(t.Context(), cmnrUser("alice"), permission.RoleAdmin), true
				case "missing_user":
					n.UserID, denied = uuid.NewString(), true
				case "missing_cm":
					n.ContactMethodID, denied = uuid.New(), true
				case "wrong_cm_user":
					n.ContactMethodID, denied = uuid.MustParse(f.cm[0]), true
				case "default_target", "multiple_target":
					cmnrRestrictBob(t, h, name == "multiple_target")
					denied = true
				case "missing_assignment", "system_without_assignment":
					_, err := h.App().DB().ExecContext(t.Context(), `DELETE FROM user_organization_assignments WHERE user_id=$1`, cmnrUser("bob"))
					require.NoError(t, err)
					denied = name == "missing_assignment"
					if !denied {
						ctx = permission.SystemContext(t.Context(), "CMNRTest")
					}
				}
				before, side := cmnrSnapshot(t, h.App().DB()), cmnrSideEffects(t, h.App().DB())
				var tx *sql.Tx
				var err error
				if explicit {
					tx, err = h.App().DB().BeginTx(ctx, nil)
					require.NoError(t, err)
					defer func() { _ = tx.Rollback() }()
				}
				created, err := h.App().NotificationRuleStore.CreateTx(ctx, tx, n)
				if denied {
					require.True(t, permission.IsPermissionError(err), "target failure must be a generic denial")
					require.Nil(t, created)
				} else {
					require.NoError(t, err)
					require.Equal(t, n.UserID, created.UserID)
				}
				if explicit {
					require.Equal(t, before, cmnrSnapshot(t, h.App().DB()))
					if denied {
						require.NoError(t, tx.Rollback())
					} else {
						require.NoError(t, tx.Commit())
					}
				}
				after := cmnrSnapshot(t, h.App().DB())
				if !denied {
					require.Contains(t, after, "NR:"+created.ID)
					delete(after, "NR:"+created.ID)
				}
				require.Equal(t, before, after)
				require.Equal(t, side, cmnrSideEffects(t, h.App().DB()))
			})
		}
	}
}

func TestCMNRPlatformAdminGraphQL(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprint("invalid_target_", invalid), func(t *testing.T) {
			h := cmnrPlatformHarness(t, "ORG_MEMBER")
			f := cmnrSeed(t, h)
			if invalid {
				cmnrRestrictBob(t, h, false)
			}
			before, side := cmnrSnapshot(t, h.App().DB()), cmnrSideEffects(t, h.App().DB())
			// Existing input shape; real signed Session; NR executes before CM.
			query := fmt.Sprintf(`mutation{deleteAll(input:[{type:contactMethod,id:%q},{type:notificationRule,id:%q},{type:contactMethod,id:%q}])}`, f.cm[3], f.nr[1], f.cm[0])
			result := h.GraphQLQueryUserT(t, harness.DefaultGraphQLAdminUserID, query)
			want := before
			if invalid {
				require.NotEmpty(t, result.Errors)
			} else {
				require.Empty(t, result.Errors)
				require.JSONEq(t, `{"deleteAll":true}`, string(result.Data))
				want = cmnrWithout(cmnrWithout(before, f, "NR", f.nr[1:2]), f, "CM", []string{f.cm[0], f.cm[3]})
			}
			require.Equal(t, want, cmnrSnapshot(t, h.App().DB()))
			require.Equal(t, side, cmnrSideEffects(t, h.App().DB()))
		})
	}
}

func TestCMNRPlatformAdminPostgresContention(t *testing.T) {
	for _, typ := range []string{"CM", "NR", "create"} {
		for _, change := range []string{"target_delete", "relationship_change", "assignment_change"} {
			t.Run(typ+"/"+change, func(t *testing.T) {
				h := cmnrPlatformHarness(t, "ORG_MEMBER")
				f := cmnrSeed(t, h)
				ctx, cancel := context.WithTimeout(cmnrPlatformHuman(t, h, harness.DefaultGraphQLAdminUserID), 15*time.Second)
				defer cancel()
				db := h.App().DB()
				blocker, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = blocker.Rollback() }()
				var pid int
				require.NoError(t, blocker.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
				table, key, id := "user_contact_methods", "id", f.cm[3]
				if typ == "NR" {
					table, id = "user_notification_rules", f.nr[3]
				}
				if change == "assignment_change" {
					table, key, id = "user_organization_assignments", "user_id", cmnrUser("bob")
				}
				_, err = blocker.ExecContext(ctx, "SELECT "+key+" FROM "+table+" WHERE "+key+"=$1 FOR UPDATE", id)
				require.NoError(t, err)
				before := cmnrSnapshot(t, db)
				result := make(chan error, 1)
				go func() {
					if typ == "create" {
						_, err := h.App().NotificationRuleStore.CreateTx(ctx, nil, &notificationrule.NotificationRule{UserID: cmnrUser("bob"), ContactMethodID: uuid.MustParse(f.cm[3]), DelayMinutes: 9})
						result <- err
					} else {
						result <- cmnrDelete(ctx, h, typ, nil, []string{idForCMNR(f, typ)})
					}
				}()
				observed := false
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					var count int
					err = db.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid))`, pid).Scan(&count)
					if err != nil || count > 0 {
						observed = count > 0
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				// Release/join before assertions so no failed test leaks workers.
				switch change {
				case "target_delete":
					_, err = blocker.ExecContext(ctx, "DELETE FROM "+table+" WHERE "+key+"=$1", id)
				case "relationship_change":
					if typ == "NR" {
						_, err = blocker.ExecContext(ctx, `UPDATE user_notification_rules SET user_id=$2,contact_method_id=$3,delay_minutes=9 WHERE id=$1`, id, cmnrUser("alice"), f.cm[0])
					} else {
						_, err = blocker.ExecContext(ctx, `UPDATE user_contact_methods SET user_id=$2 WHERE id=$1`, id, cmnrUser("alice"))
					}
				case "assignment_change":
					_, err = blocker.ExecContext(ctx, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, cmnrUser("bob"), organization.DefaultOrganizationID)
				}
				commitErr := blocker.Commit()
				workerErr := <-result
				require.NoError(t, err)
				require.NoError(t, commitErr)
				require.True(t, observed, "must observe PostgreSQL blocking on the exact independent transaction")
				t.Logf("observed PostgreSQL blocker pid=%d table=%s; post-wait Store result checked", pid, table)
				if change == "target_delete" && typ != "create" {
					require.NoError(t, workerErr)
				} else {
					require.True(t, permission.IsPermissionError(workerErr), "wait/recheck must reject invalid relationships")
				}
				after := cmnrSnapshot(t, db)
				if change == "assignment_change" {
					require.Equal(t, before, after)
				}
				if change == "target_delete" {
					deletedType := typ
					if typ == "create" {
						deletedType = "CM"
					}
					require.Equal(t, cmnrWithout(before, f, deletedType, []string{idForCMNR(f, typ)}), after)
				}
				if change == "relationship_change" {
					changed := "CM:" + f.cm[3]
					if typ == "NR" {
						changed = "NR:" + f.nr[3]
					}
					require.NotEqual(t, before[changed], after[changed])
					delete(before, changed)
					delete(after, changed)
					require.Equal(t, before, after, "only the independent blocker may change a row")
				}
			})
		}
	}
}

func idForCMNR(f cmnrFixture, typ string) string {
	if typ == "NR" {
		return f.nr[3]
	}
	return f.cm[3]
}

func TestCMNRPlatformAdminRetainsPrivateOwnerBoundary(t *testing.T) {
	h := cmnrPlatformHarness(t, "ORG_MEMBER")
	f := cmnrSeed(t, h)
	// Same-Home non-owner privacy remains in force even for trusted Admin.
	query := fmt.Sprintf(`{userContactMethod(id:%q){dest{args}}}`, f.cm[0])
	result := h.GraphQLQueryUserT(t, harness.DefaultGraphQLAdminUserID, query)
	require.Empty(t, result.Errors)
	require.JSONEq(t, `{"userContactMethod":{"dest":{"args":{}}}}`, string(result.Data))
	result = h.GraphQLQueryUserT(t, harness.DefaultGraphQLAdminUserID, fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,private:false})}`, f.cm[0]))
	require.NotEmpty(t, result.Errors, "trusted PlatformAdmin must not clear another owner's privacy flag")
}

func TestCMNRPlatformAdminInvalidRelationshipBatch(t *testing.T) {
	for _, typ := range []string{"CM", "NR"} {
		t.Run(typ, func(t *testing.T) {
			h := cmnrPlatformHarness(t, "ORG_MEMBER")
			f := cmnrSeed(t, h)
			// Existing DB trigger validates NR writes, not a later CM owner
			// change. The final Store guard must detect this inconsistency.
			_, err := h.App().DB().ExecContext(t.Context(), `UPDATE user_contact_methods SET user_id=$2 WHERE id=$1`, f.cm[3], cmnrUser("alice"))
			require.NoError(t, err)
			before, side := cmnrSnapshot(t, h.App().DB()), cmnrSideEffects(t, h.App().DB())
			ids := []string{f.cm[0], f.cm[3]}
			if typ == "NR" {
				ids = []string{f.nr[0], f.nr[3]}
			}
			err = cmnrDelete(cmnrPlatformHuman(t, h, harness.DefaultGraphQLAdminUserID), h, typ, nil, ids)
			require.True(t, permission.IsPermissionError(err))
			require.Equal(t, before, cmnrSnapshot(t, h.App().DB()))
			require.Equal(t, side, cmnrSideEffects(t, h.App().DB()))
		})
	}
}

func TestCMNRPlatformAdminGraphQLAdmission(t *testing.T) {
	h := cmnrPlatformHarness(t, "ORG_MEMBER")
	f := cmnrSeed(t, h)
	admin := harness.DefaultGraphQLAdminUserID
	before := cmnrSnapshot(t, h.App().DB())
	query := fmt.Sprintf(`mutation{deleteAll(input:[{type:contactMethod,id:%q}])}`, f.cm[3])
	// The same signed Session must observe the downgrade on the next request.
	_, err := h.App().DB().ExecContext(t.Context(), `UPDATE users SET role='user' WHERE id=$1`, admin)
	require.NoError(t, err)
	result := h.GraphQLQueryUserT(t, admin, query)
	require.NotEmpty(t, result.Errors)
	require.Equal(t, before, cmnrSnapshot(t, h.App().DB()))
	_, err = h.App().DB().ExecContext(t.Context(), `UPDATE users SET role='admin' WHERE id=$1`, admin)
	require.NoError(t, err)
	// Canonical auth still authenticates the real Admin, but admission cannot
	// construct a valid Human EC. The Store must reject its legacy Admin flag.
	_, err = h.App().DB().ExecContext(t.Context(), `DELETE FROM user_organization_assignments WHERE user_id=$1`, admin)
	require.NoError(t, err)
	result = h.GraphQLQueryUserT(t, admin, query)
	require.NotEmpty(t, result.Errors)
	require.Equal(t, before, cmnrSnapshot(t, h.App().DB()))
}

func TestCMNRPlatformAdminDoesNotGrantOtherResourceGlobalDelete(t *testing.T) {
	h := cmnrPlatformHarness(t, "ORG_MEMBER")
	f := cmnrSeed(t, h)
	id := uuid.NewString()
	_, err := h.App().DB().ExecContext(t.Context(), `INSERT INTO escalation_policies(id,name,organization_id) VALUES($1,'S0B foreign policy',$2)`, id, cmnrUser("org-b"))
	require.NoError(t, err)
	before := cmnrSnapshot(t, h.App().DB())
	query := fmt.Sprintf(`mutation{deleteAll(input:[{type:escalationPolicy,id:%q},{type:notificationRule,id:%q}])}`, id, f.nr[0])
	wait := h.ExpectBackendError("delete escalation policies: sql: no rows in result set")
	result := h.GraphQLQueryUserT(t, harness.DefaultGraphQLAdminUserID, query)
	wait()
	require.NotEmpty(t, result.Errors)
	require.Equal(t, before, cmnrSnapshot(t, h.App().DB()))
	var exists bool
	require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM escalation_policies WHERE id=$1)`, id).Scan(&exists))
	require.True(t, exists)
}
