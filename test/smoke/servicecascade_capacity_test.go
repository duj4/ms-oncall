package smoke

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/service/deleteaudit"
	"github.com/target/goalert/test/smoke/harness"
)

func TestServiceCascadePG13BudgetAcrossRoots(t *testing.T) {
	for _, count := range []int{deleteaudit.MaxEffects, deleteaudit.MaxEffects + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			root, other := h.UUID("service-b"), uuid.NewString()
			_, err := db.Exec(`INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,'SD3 capacity second')`, other, h.UUID("org-b"), h.UUID("policy-b"))
			require.NoError(t, err)
			_, err = db.Exec(`INSERT INTO alerts(service_id,summary,status) SELECT CASE WHEN n%2=0 THEN $1::uuid ELSE $2::uuid END,'SD3 capacity','closed' FROM generate_series(1,$3) n`, root, other, count)
			require.NoError(t, err)
			ok, err := sd3App(h).Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root), sd3Target(assignment.TargetTypeService, other)})
			if count == deleteaudit.MaxEffects {
				require.NoError(t, err)
				require.True(t, ok)
				require.Equal(t, count, len(sd3Effects(t, h, root))+len(sd3Effects(t, h, other)))
			} else {
				require.Error(t, err)
				require.False(t, ok)
				require.Equal(t, 1, serviceManagementCount(t, h, "services", root))
				require.Equal(t, 1, serviceManagementCount(t, h, "services", other))
				require.Zero(t, sd1Count(t, h, "committed"))
				var n int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM alerts WHERE service_id IN ($1,$2)`, root, other).Scan(&n))
				require.Equal(t, count, n)
			}
		})
	}
}

func TestServiceCascadePG03RawInputLimitsBeforeDeduplication(t *testing.T) {
	for _, count := range []int{50, 51} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			h := sd1Harness(t)
			ikSetAuthority(t, h, "ORG_MEMBER", true)
			root := h.UUID("service-b")
			key, safe := sd3Key(t, h, root)
			var input []assignment.RawTarget
			for range 50 {
				input = append(input, sd3Target(assignment.TargetTypeService, root))
			}
			for range count {
				input = append(input, sd3Target(assignment.TargetTypeIntegrationKey, key.String()))
			}
			ok, err := sd3App(h).Mutation().DeleteAll(servicePlatformAdminContext(t, h), input)
			if count == 50 {
				require.NoError(t, err)
				require.True(t, ok)
				effects := sd3Effects(t, h, root)
				require.Len(t, effects, 1)
				require.Equal(t, safe, *effects[0].ResourceUUID)
				require.Equal(t, "EXPLICIT", effects[0].Provenance)
			} else {
				require.Error(t, err)
				require.False(t, ok)
				require.Zero(t, sd1Count(t, h, "committed"))
				require.Equal(t, 1, serviceManagementCount(t, h, "services", root))
				var exists bool
				require.NoError(t, h.App().DB().QueryRow(`SELECT EXISTS(SELECT FROM integration_keys WHERE id=$1)`, key).Scan(&exists))
				require.True(t, exists)
			}
		})
	}
}

func TestServiceCascadePG13JSONBByteBudgetAcrossRoots(t *testing.T) {
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			root, other := h.UUID("service-b"), uuid.NewString()
			owner, ownerOrg := uuid.New(), uuid.MustParse(harness.SmokeOrganizationID)
			id := int64(1000000000000000000)
			f := deleteaudit.Effect{EffectID: uuid.New(), ResourceType: deleteaudit.ServiceFavorite, ResourceNumericID: &id, OwnerUserID: &owner, OwnerOrganizationID: &ownerOrg, OwnerOrgResolution: "known_normal", TargetOrganizationID: uuid.MustParse(h.UUID("org-b")), Relation: "service.favorite", Change: "relationship_removed", Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: "service_delete"}
			raw, err := json.Marshal([]deleteaudit.Effect{f})
			require.NoError(t, err)
			var unit int
			require.NoError(t, db.QueryRow(`SELECT octet_length($1::jsonb::text)`, string(raw)).Scan(&unit))
			count := (deleteaudit.MaxJSONBytes + unit - 1) / unit
			reduce := count*unit - deleteaudit.MaxJSONBytes - extra
			require.Positive(t, reduce)
			require.LessOrEqual(t, count, deleteaudit.MaxEffects)
			_, err = db.Exec(`INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,'SD3 byte capacity')`, other, h.UUID("org-b"), h.UUID("policy-b"))
			require.NoError(t, err)
			_, err = db.Exec(`INSERT INTO users(id,name,role) SELECT gen_random_uuid(),'SD3 byte owner','user' FROM generate_series(1,$1)`, count)
			require.NoError(t, err)
			_, err = db.Exec(`INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,matched_count,authoritative_evaluated_at,source_config_version)
		 SELECT id,$1,'NORMAL',$1,'ORG_MEMBER','EXACTLY_ONE',1,now(),'sd3-byte-capacity' FROM users WHERE name='SD3 byte owner'`, harness.SmokeOrganizationID)
			require.NoError(t, err)
			_, err = db.Exec(`INSERT INTO user_favorites(id,user_id,tgt_service_id)
		 SELECT CASE WHEN n<=$3 THEN 100000000000000000+n ELSE 1000000000000000000+n END,id,CASE WHEN n%2=0 THEN $1::uuid ELSE $2::uuid END
		 FROM (SELECT id,row_number() OVER(ORDER BY id) n FROM users WHERE name='SD3 byte owner') owners`, root, other, reduce)
			require.NoError(t, err)
			ok, err := sd3App(h).Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root), sd3Target(assignment.TargetTypeService, other)})
			if extra == 0 {
				require.NoError(t, err)
				require.True(t, ok)
				var bytes, effects, roots int
				require.NoError(t, db.QueryRow(`SELECT sum(octet_length(effects::text)),sum(jsonb_array_length(effects)),count(*) FROM service_delete_audit_events WHERE outcome='committed'`).Scan(&bytes, &effects, &roots))
				require.Equal(t, deleteaudit.MaxJSONBytes, bytes)
				require.Equal(t, count, effects)
				require.Equal(t, 2, roots)
			} else {
				require.Error(t, err)
				require.False(t, ok)
				require.Zero(t, sd1Count(t, h, "committed"))
				require.Equal(t, 1, serviceManagementCount(t, h, "services", root))
				require.Equal(t, 1, serviceManagementCount(t, h, "services", other))
				var remaining int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM user_favorites WHERE tgt_service_id IN($1,$2)`, root, other).Scan(&remaining))
				require.Equal(t, count, remaining)
			}
			t.Logf("two roots: actual aggregate JSONB limit %d bytes + %d; %d complete effects", deleteaudit.MaxJSONBytes, extra, count)
		})
	}
}
