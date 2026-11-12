package smoke

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/organization"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/test/smoke/harness"
)

func TestSRDeleteAuditFavoriteContexts(t *testing.T) {
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	db := h.App().DB()
	s, r, other := sd6Root(t, h, sraudit.Schedule, harness.SmokeOrganizationID), sd6Root(t, h, sraudit.Rotation, harness.SmokeOrganizationID), sd6Root(t, h, sraudit.Schedule, harness.SmokeOrganizationID)
	defaultOwner, unknown := uuid.NewString(), uuid.NewString()
	_, err := db.Exec(`INSERT INTO users(id,name,role) VALUES($1,'SYNTHETIC_PRIVATE','user'),($2,'SYNTHETIC_PRIVATE','user')`, defaultOwner, unknown)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,matched_count,authoritative_evaluated_at,source_config_version) VALUES($1,$2,'DEFAULT',NULL,'NONE','ZERO',0,now(),'sd6-test')`, defaultOwner, organization.DefaultOrganizationID)
	require.NoError(t, err)
	expected := map[int64]string{}
	for _, row := range []struct {
		owner      string
		s, r       any
		resolution string
	}{{h.UUID("user-a"), s, nil, "known_normal"}, {defaultOwner, nil, r, "known_default"}, {unknown, s, r, "unknown"}} {
		var id int64
		require.NoError(t, db.QueryRow(`INSERT INTO user_favorites(user_id,tgt_schedule_id,tgt_rotation_id) VALUES($1,$2,$3) RETURNING id`, row.owner, row.s, row.r).Scan(&id))
		expected[id] = row.resolution
	}
	var untouched int64
	require.NoError(t, db.QueryRow(`INSERT INTO user_favorites(user_id,tgt_schedule_id) VALUES($1,$2) RETURNING id`, unknown, other).Scan(&untouched))
	response := stepOrganizationQuery(t, h, sd6Query(sraudit.Schedule, []string{s}, fmt.Sprintf(`{type:rotation,id:%q}`, r)))
	require.Empty(t, response.Errors)
	se, re := sd6Effects(t, h, s), sd6Effects(t, h, r)
	require.Len(t, se, 1)
	require.Len(t, re, 2)
	for _, f := range append(se, re...) {
		require.Equal(t, expected[*f.ResourceNumericID], f.Favorite.OwnerOrgResolution)
		delete(expected, *f.ResourceNumericID)
	}
	require.Empty(t, expected)
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM user_favorites WHERE id=$1`, untouched).Scan(&n))
	require.Equal(t, 1, n)
	require.Equal(t, 1, serviceManagementCount(t, h, "users", defaultOwner))
	require.Equal(t, 1, serviceManagementCount(t, h, "users", unknown))
	require.NotContains(t, sd6Rows(t, h), "SYNTHETIC_")
}

func TestSRDeleteAuditForeignActions(t *testing.T) {
	for _, typ := range []string{sraudit.Schedule, sraudit.Rotation} {
		for _, pa := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/pa=%t", typ, pa), func(t *testing.T) {
				t.Parallel()
				h := sd1Harness(t)
				ikSetAuthority(t, h, "ORG_ADMIN", pa)
				root := sd6Root(t, h, typ, harness.SmokeOrganizationID)
				policy := sd5EP(t, h, h.UUID("org-b"))
				step := sd5Step(t, h, policy)
				action := sd6Action(t, h, step, typ, root)
				expected := h.ExpectBackendError("sql: no rows in result set")
				response := stepOrganizationQuery(t, h, sd6Query(typ, []string{root}, fmt.Sprintf(`{type:service,id:%q}`, h.UUID("service-a"))))
				expected()
				require.NotEmpty(t, response.Errors)
				require.Zero(t, sd6Count(t, h))
				require.Equal(t, 1, serviceManagementCount(t, h, typ+"s", root))
				require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policy_actions", action))
				require.Equal(t, 1, serviceManagementCount(t, h, "services", h.UUID("service-a")))
				require.NotContains(t, fmt.Sprint(response.Errors), policy)
			})
		}
	}
}

func TestSRDeleteAuditMixedOrganizationScopes(t *testing.T) {
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	s, r := sd6Root(t, h, sraudit.Schedule, harness.SmokeOrganizationID), sd6Root(t, h, sraudit.Rotation, h.UUID("org-b"))
	response := stepOrganizationQuery(t, h, sd6Query(sraudit.Schedule, []string{s}, fmt.Sprintf(`{type:rotation,id:%q}`, r)))
	require.Empty(t, response.Errors)
	require.Equal(t, 2, sd6Count(t, h))
	var count int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE home_organization_id=$1 AND ((root_id=$2 AND target_organization_id=$1) OR (root_id=$3 AND target_organization_id=$4))`, harness.SmokeOrganizationID, s, r, h.UUID("org-b")).Scan(&count))
	require.Equal(t, 2, count)
}
