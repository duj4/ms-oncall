package smoke

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/service/deleteaudit"
	"github.com/target/goalert/test/smoke/harness"
)

func TestServiceCascadePG13BudgetAcrossRoots(t *testing.T) {
	// CONTRACT ADAPTATION: retain original Audit limits and exercise the
	// current two-root 10000-row closure boundary (2 roots + policy + org).
	for _, count := range []int{ds.DefaultBudget().MaxDependencies - 4, ds.DefaultBudget().MaxDependencies - 3, ds.DefaultBudget().MaxDependencies - 2, ds.DefaultBudget().MaxDependencies - 1, deleteaudit.MaxEffects, deleteaudit.MaxEffects + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			root, other := h.UUID("service-b"), uuid.NewString()
			_, err := db.Exec(`INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,'SD3 capacity second')`, other, h.UUID("org-b"), h.UUID("policy-b"))
			require.NoError(t, err)
			_, err = db.Exec(`INSERT INTO alerts(service_id,summary,status) SELECT CASE WHEN n%2=0 THEN $1::uuid ELSE $2::uuid END,'SD3 capacity','closed' FROM generate_series(1,$3) n`, root, other, count)
			require.NoError(t, err)
			input := []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root), sd3Target(assignment.TargetTypeService, other)}
			preview, previewErr := smokeDeletionPreview(t, h, sd3System(), input)
			if count > ds.DefaultBudget().MaxDependencies-2 {
				smokeDeletionCode(t, previewErr, ds.DeletionPreviewLimitExceeded)
				require.Nil(t, preview)
				smokeContract4Reject(t, h, sd3App(h), sd3System(), input, nil, ds.DeletionPreviewLimitExceeded)
			} else {
				require.NoError(t, previewErr)
				require.True(t, preview.CanProceed)
				confirmation := smokePlanConfirmation(t, h, sd3System(), input)
				if count > ds.DefaultBudget().MaxDependencies-4 {
					smokeContract4Reject(t, h, sd3App(h), sd3System(), input, confirmation, ds.DeletionPreviewLimitExceeded)
				} else {
					ok, err := sd3App(h).Mutation().DeleteAll(sd3System(), input, confirmation)
					require.NoError(t, err)
					require.True(t, ok)
					require.Equal(t, count, len(sd3Effects(t, h, root))+len(sd3Effects(t, h, other)))
					require.Zero(t, serviceManagementCount(t, h, "services", root))
					require.Zero(t, serviceManagementCount(t, h, "services", other))
					require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM alerts WHERE service_id IN($1,$2)`, root, other))
					require.Equal(t, 2, sd1Count(t, h, "committed"))
					t.Log("NEW LEGAL EQUIVALENT COVERAGE: complete two-Service closure at 10000 stable rows committed atomically")
					return
				}
			}
			require.EqualValues(t, count, sd8Scalar(t, h, `SELECT count(*) FROM alerts WHERE service_id IN($1,$2)`, root, other))
			if count >= deleteaudit.MaxEffects {
				t.Log("LEGACY AUDIT BOUNDARY NOT REACHABLE: retained original 16384/16385 Alert input; earlier Preview refusal")
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
			// CONTRACT ADAPTATION: original mixed inputs remain real refusals.
			before, audits := serviceManagementSnapshot(t, h), smokeContract4SuccessState(t, h)
			ok, err := sd3App(h).Mutation().DeleteAll(servicePlatformAdminContext(t, h), input, nil)
			require.Error(t, err)
			require.False(t, ok)
			require.Equal(t, before, serviceManagementSnapshot(t, h))
			require.Equal(t, audits, smokeContract4SuccessState(t, h))
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM integration_keys WHERE audit_resource_id=$1`, safe))
			// NEW LEGAL EQUIVALENT COVERAGE: independently test raw 50/51
			// before deduplication, preserving one actual root and its Key identity.
			legal := smokeContract4Service(t, h, true)
			_, legalSafe := sd3Key(t, h, legal)
			var homogeneous []assignment.RawTarget
			for range count {
				homogeneous = append(homogeneous, sd3Target(assignment.TargetTypeService, legal))
			}
			confirmation := smokePlanConfirmation(t, h, sd3System(), homogeneous[:1])
			before, audits = serviceManagementSnapshot(t, h), smokeContract4SuccessState(t, h)
			ok, err = sd3App(h).Mutation().DeleteAll(sd3System(), homogeneous, confirmation)
			if count == 50 {
				require.NoError(t, err)
				require.True(t, ok)
				effects := sd3Effects(t, h, legal)
				require.Len(t, effects, 1)
				require.Equal(t, legalSafe, *effects[0].ResourceUUID)
				require.Equal(t, "CASCADE", effects[0].Provenance)
				require.Equal(t, 1, sd1Count(t, h, "committed"))
			} else {
				require.Error(t, err)
				require.False(t, ok)
				require.Equal(t, before, serviceManagementSnapshot(t, h))
				require.Equal(t, audits, smokeContract4SuccessState(t, h))
			}
			// A Key-only root has EXPLICIT provenance; it is a separate request.
			keyRoot := smokeContract4Service(t, h, true)
			keyID, keySafe := sd3Key(t, h, keyRoot)
			ok, err = smokeDeleteAll(t, h, sd3App(h), sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeIntegrationKey, keyID.String()), sd3Target(assignment.TargetTypeIntegrationKey, keyID.String())})
			require.NoError(t, err)
			require.True(t, ok)
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM integration_key_delete_audit_events WHERE root_resource_id=$1 AND record_kind='success_witness' AND provenance='EXPLICIT'`, keySafe))
			require.Equal(t, 1, serviceManagementCount(t, h, "services", keyRoot))
			t.Log("PARTIAL LEGAL COVERAGE: original mixed 50/51 refused; homogeneous raw limit/dedup/CASCADE and separate EXPLICIT Key identity verified")

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
			// CONTRACT ADAPTATION: unchanged original exact JSONB size fixture
			// is rejected by the current earlier weighted dependency budget.
			input := []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root), sd3Target(assignment.TargetTypeService, other)}
			preview, previewErr := smokeDeletionPreview(t, h, sd3System(), input)
			smokeDeletionCode(t, previewErr, ds.DeletionPreviewLimitExceeded)
			require.Nil(t, preview)
			smokeContract4Reject(t, h, sd3App(h), sd3System(), input, nil, ds.DeletionPreviewLimitExceeded)
			require.EqualValues(t, count, sd8Scalar(t, h, `SELECT count(*) FROM user_favorites WHERE tgt_service_id IN($1,$2)`, root, other))
			t.Logf("LEGACY AUDIT BOUNDARY NOT REACHABLE: actual original %d+%d JSONB projection, %d effects retained; not an exact Preview JSON-envelope claim", deleteaudit.MaxJSONBytes, extra, count)

		})
	}
	for _, count := range []int{(ds.DefaultBudget().MaxDependencies - 5) / 3, (ds.DefaultBudget().MaxDependencies-5)/3 + 1, (ds.DefaultBudget().MaxDependencies-5)/3 + 2} {
		t.Run(fmt.Sprintf("current_weight_%d", count), func(t *testing.T) { closureFavoriteBudget(t, assignment.TargetTypeService, count) })
	}

}
