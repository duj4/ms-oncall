package smoke

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/organization"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/test/smoke/harness"
	"strings"
	"testing"
)

func TestSRDeleteAuditHTTPRoles(t *testing.T) {
	for _, typ := range []string{sraudit.Schedule, sraudit.Rotation} {
		t.Run(typ, func(t *testing.T) {
			t.Parallel()
			targetType := assignment.TargetTypeSchedule
			if typ == sraudit.Rotation {
				targetType = assignment.TargetTypeRotation
			}
			_ = targetType

			for _, mode := range []string{"org_admin", "foreign_pa", "default_pa", "same_org_batch", "member", "foreign_org_admin", "cross_org_pa", "missing", "valid_foreign_org_admin", "pa_missing"} {
				t.Run(mode, func(t *testing.T) {
					t.Parallel()
					h := sd1Harness(t)
					db := h.App().DB()
					pa := strings.Contains(mode, "pa")
					ikSetAuthority(t, h, "ORG_ADMIN", pa)
					if mode == "member" {
						ikSetAuthority(t, h, "ORG_MEMBER", false)
					}
					home, target := harness.SmokeOrganizationID, harness.SmokeOrganizationID
					if mode == "foreign_pa" || mode == "default_pa" || mode == "foreign_org_admin" {
						target = h.UUID("org-b")
					}
					if mode == "default_pa" {
						home = organization.DefaultOrganizationID
						_, err := db.Exec(`UPDATE user_organization_assignments SET effective_organization_id=$2,effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, h.UUID("user-a"), home)
						require.NoError(t, err)
					}
					root := sd6Root(t, h, typ, target)
					ids := []string{root}
					if mode == "same_org_batch" {
						ids = append(ids, sd6Root(t, h, typ, target))
					}
					if mode == "cross_org_pa" {
						ids = append(ids, sd6Root(t, h, typ, h.UUID("org-b")))
					}
					if mode == "missing" || mode == "pa_missing" {
						ids = append(ids, uuid.NewString())
					}
					if mode == "valid_foreign_org_admin" {
						ids = append(ids, sd6Root(t, h, typ, h.UUID("org-b")))
					}
					var expected func()
					if mode == "foreign_org_admin" || mode == "cross_org_pa" || mode == "missing" || mode == "pa_missing" || mode == "valid_foreign_org_admin" {
						expected = h.ExpectBackendError("sql: no rows in result set")
					}
					response := stepOrganizationQuery(t, h, sd6Query(typ, append(ids, root)))
					if expected != nil {
						expected()
					}
					allowed := mode == "org_admin" || mode == "foreign_pa" || mode == "default_pa" || mode == "same_org_batch"
					if !allowed {
						require.NotEmpty(t, response.Errors)
						require.Zero(t, sd6Count(t, h))
						require.Equal(t, 1, serviceManagementCount(t, h, typ+"s", root))
						return
					}
					require.Empty(t, response.Errors)
					require.Equal(t, len(ids), sd6Count(t, h))
					var events []map[string]any
					require.NoError(t, json.Unmarshal([]byte(sd6Rows(t, h)), &events))
					var request, execution, attempt any
					for _, e := range events {
						require.Equal(t, h.UUID("user-a"), e["actor_id"])
						require.Equal(t, home, e["home_organization_id"])
						require.Equal(t, target, e["target_organization_id"])
						require.Equal(t, "EXPLICIT", e["provenance"])
						require.Equal(t, "explicit_sql", e["deletion_mechanism"])
						require.Equal(t, "explicit_target", e["cause"])
						require.Empty(t, e["effects"])
						require.Equal(t, 0, serviceManagementCount(t, h, typ+"s", e["root_id"].(string)))
						if request == nil {
							request, execution, attempt = e["request_id"], e["execution_id"], e["attempt_id"]
						}
						require.Equal(t, request, e["request_id"])
						require.Equal(t, execution, e["execution_id"])
						require.Equal(t, attempt, e["attempt_id"])
					}
					expected = h.ExpectBackendError("sql: no rows in result set")
					response = stepOrganizationQuery(t, h, sd6Query(typ, ids))
					expected()
					require.NotEmpty(t, response.Errors)
					require.Equal(t, len(ids), sd6Count(t, h))
				})
			}

		})
	}
}
func TestSRDeleteAuditRawLimitsAndSystem(t *testing.T) {
	for _, typ := range []string{sraudit.Schedule, sraudit.Rotation} {
		t.Run(typ, func(t *testing.T) {
			t.Parallel()
			targetType := assignment.TargetTypeSchedule
			if typ == sraudit.Rotation {
				targetType = assignment.TargetTypeRotation
			}
			_ = targetType

			h := sd1Harness(t)
			ikSetAuthority(t, h, "ORG_ADMIN", false)
			root := sd6Root(t, h, typ, harness.SmokeOrganizationID)
			for _, n := range []int{51, 50} {
				ids := make([]string, n)
				for i := range ids {
					ids[i] = root
				}
				r := stepOrganizationQuery(t, h, sd6Query(typ, ids))
				if n == 51 {
					require.NotEmpty(t, r.Errors)
					require.Zero(t, sd6Count(t, h))
					require.NotContains(t, sd6Rows(t, h), root)
				} else {
					require.Empty(t, r.Errors)
					require.Equal(t, 1, sd6Count(t, h))
				}
			}
			ids := []string{}
			for i := 0; i < 50; i++ {
				ids = append(ids, sd6Root(t, h, typ, harness.SmokeOrganizationID))
			}
			r := stepOrganizationQuery(t, h, sd6Query(typ, ids))
			require.Empty(t, r.Errors)
			require.Equal(t, 51, sd6Count(t, h))
			r = stepOrganizationQuery(t, h, sd6Query(typ, []string{"malformed"}))
			require.NotEmpty(t, r.Errors)
			require.Equal(t, 51, sd6Count(t, h))
			app := sd5App(h)
			missing := uuid.NewString()
			for i := 0; i < 2; i++ {
				ok, err := app.Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(targetType, missing)})
				require.NoError(t, err)
				require.True(t, ok)
			}
			require.Equal(t, 51, sd6Count(t, h))
			// No authenticated/canonical authority: no resource lookup attribution.
			_, err := app.Mutation().DeleteAll(context.Background(), []assignment.RawTarget{sd3Target(targetType, uuid.NewString())})
			require.Error(t, err)
			var unknownRoots int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM escalation_policy_delete_audit_events WHERE actor_kind='unknown' AND root_id IS NOT NULL`).Scan(&unknownRoots))
			require.Zero(t, unknownRoots)

		})
	}
}
