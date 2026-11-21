package smoke

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/target/goalert/schedule"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/test/smoke/harness"
)

// CONTRACT ADAPTATION: inspect the real GraphQL resolver error, including its
// alias. A helper refusing to construct a Preview is not a mutation rejection.
func closureHTTPError(t *testing.T, response map[string]json.RawMessage, alias, code string) {
	t.Helper()
	var errors []struct {
		Path       []any `json:"path"`
		Extensions struct {
			Code string `json:"code"`
		} `json:"extensions"`
	}
	require.NoError(t, json.Unmarshal(response["errors"], &errors))
	require.Len(t, errors, 1)
	require.Equal(t, alias, errors[0].Path[0])
	require.Equal(t, code, errors[0].Extensions.Code)
}

// FAULT COVERAGE RESTORATION: sequences survive rollback, so an aborted real
// PostgreSQL trigger cannot be mistaken for a refusal before Audit Detail DML.
func closureSessionFault(t *testing.T, h *harness.Harness, install bool) {
	t.Helper()
	if install {
		sd8Exec(t, h, `CREATE SEQUENCE closure_session_hits;
CREATE FUNCTION closure_session_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN
PERFORM nextval('closure_session_hits'); RAISE EXCEPTION 'SYNTHETIC_PRIVATE_SQL'; END;$$;
CREATE TRIGGER closure_session_fault BEFORE INSERT ON user_session_revoke_audit_details FOR EACH ROW EXECUTE FUNCTION closure_session_fault()`)
		return
	}
	sd8Exec(t, h, `DROP TRIGGER closure_session_fault ON user_session_revoke_audit_details; DROP FUNCTION closure_session_fault(); DROP SEQUENCE closure_session_hits`)
}

func closureSessionFaultHits(t *testing.T, h *harness.Harness) int64 {
	t.Helper()
	return sd8Scalar(t, h, `SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM closure_session_hits`)
}

// NEW LEGAL EQUIVALENT COVERAGE: a Favorite's single incoming edge already
// contains its two retained references, so its weight is 3. Stabilization also
// charges roots, Users, assignments and Organization rows. Keep all production
// limits; exercise the last legal stable closure, the next Guard refusal, and
// the first weighted Preview refusal. This is not the old 8 MiB Audit boundary
// and does not claim an exact Preview JSON-envelope boundary.
func closureFavoriteBudget(t *testing.T, kind assignment.TargetType, count int) {
	t.Helper()
	h := sd1Harness(t)
	root, other := "", ""
	app := sd5App(h)
	column, auditTable := "tgt_escalation_policy_id", "escalation_policy_delete_audit_events"
	if kind == assignment.TargetTypeService {
		root, other = smokeContract4Service(t, h, true), smokeContract4Service(t, h, true)
		app, column, auditTable = sd3App(h), "tgt_service_id", "service_delete_audit_events"
	} else {
		root, other = sd5EP(t, h, harness.SmokeOrganizationID), sd5EP(t, h, harness.SmokeOrganizationID)
	}
	sd8Exec(t, h, `INSERT INTO users(id,name,role) SELECT gen_random_uuid(),'closure-favorite-owner','user' FROM generate_series(1,$1)`, count)
	sd8Exec(t, h, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,matched_count,authoritative_evaluated_at,source_config_version)
SELECT id,$1,'NORMAL',$1,'ORG_MEMBER','EXACTLY_ONE',1,now(),'closure-synthetic' FROM users WHERE name='closure-favorite-owner'`, harness.SmokeOrganizationID)
	sd8Exec(t, h, `INSERT INTO user_favorites(user_id,`+column+`) SELECT id,CASE WHEN n%2=0 THEN $1::uuid ELSE $2::uuid END FROM (SELECT id,row_number() OVER(ORDER BY id) n FROM users WHERE name='closure-favorite-owner') u`, root, other)
	input := []assignment.RawTarget{{Type: kind, ID: root}, {Type: kind, ID: other}}
	p, err := smokeDeletionPreview(t, h, sd3System(), input)
	weight, stableBase := count*3, 4
	if kind == assignment.TargetTypeService {
		weight += 2
		stableBase++
	}
	if weight > ds.DefaultBudget().MaxDependencies {
		smokeDeletionCode(t, err, ds.DeletionPreviewLimitExceeded)
		require.Nil(t, p)
		smokeContract4Reject(t, h, app, sd3System(), input, nil, ds.DeletionPreviewLimitExceeded)
		require.EqualValues(t, count, sd8Scalar(t, h, `SELECT count(*) FROM user_favorites WHERE `+column+` IN($1,$2)`, root, other))
		return
	}
	require.NoError(t, err)
	require.True(t, p.Complete)
	require.True(t, p.CanProceed)
	require.False(t, p.RequiresConfirmation, "Favorite-only impacts are informational")
	reversed := []assignment.RawTarget{input[1], input[0]}
	confirmation := smokePlanConfirmation(t, h, sd3System(), reversed)
	require.Equal(t, p.ImpactVersion, confirmation.ExpectedImpactVersion, "root order cannot change the complete dependency version")
	if stableBase+count*3 > ds.DefaultBudget().MaxDependencies {
		smokeContract4Reject(t, h, app, sd3System(), input, confirmation, ds.DeletionPreviewLimitExceeded)
		return
	}
	ok, err := app.Mutation().DeleteAll(sd3System(), input, confirmation)
	require.NoError(t, err)
	require.True(t, ok)
	predicate := `record_kind='success_witness'`
	if kind == assignment.TargetTypeService {
		predicate = `outcome='committed'`
	}
	require.EqualValues(t, count, sd8Scalar(t, h, `SELECT sum(jsonb_array_length(effects)) FROM `+auditTable+` WHERE `+predicate))
	require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(*) FROM `+auditTable+` WHERE `+predicate))
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_favorites WHERE `+column+` IN($1,$2)`, root, other))
	require.EqualValues(t, count, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE name='closure-favorite-owner'`))
	t.Logf("NEW LEGAL EQUIVALENT COVERAGE: %d weighted dependencies; complete two-root business/Audit Commit", weight)
}

// NEW LEGAL EQUIVALENT COVERAGE: EP/Service 8 MiB Audit envelopes are not
// Collector's 1 MiB schedule JSON boundary. Exercise the latter separately on
// a legal User root (which really scans the full persisted V1 envelopes).
// RFC3339 permits arbitrary fractional precision: trailing zeroes keep the
// NextNotification instant unchanged while measuring exact PostgreSQL JSONB
// text bytes. The real schedule Rule decoder validates the fixture too.
func TestCoverageClosureJSONEnvelopeBudget(t *testing.T) {
	h := sd1Harness(t)
	sched, channel := h.UUID("schedule-a"), uuid.NewString()
	sd8Exec(t, h, `INSERT INTO notification_channels(id,name,type,value) VALUES($1,'closure JSON','WEBHOOK','https://synthetic.invalid/closure')`, channel)
	const maxBytes = 1 << 20
	for _, bytes := range []int{maxBytes - 1, maxBytes, maxBytes + 1} {
		t.Run(fmt.Sprint(bytes), func(t *testing.T) {
			owner := smokeOwnedUser(t, h)
			input := []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: owner}}
			// Obtain a real admissible Preview before changing the envelope.
			sd8Exec(t, h, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,'{"V1":{"TemporarySchedules":[],"OnCallNotificationRules":[]}}') ON CONFLICT(schedule_id) DO UPDATE SET data=excluded.data`, sched)
			confirmation := smokePlanConfirmation(t, h, sd3System(), input)
			prefix := fmt.Sprintf(`{"V1":{"TemporarySchedules":[],"OnCallNotificationRules":[{"ID":%q,"ChannelID":%q,"NextNotification":"2000-01-01T00:00:00.`, sched+":0", channel)
			suffix := `Z"}]}}`
			base := prefix + "0" + suffix
			var overhead, others int
			require.NoError(t, h.App().DB().QueryRow(`SELECT octet_length($1::jsonb::text)-1`, base).Scan(&overhead))
			require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(sum(octet_length(data::text)),0) FROM schedule_data WHERE schedule_id<>$1`, sched).Scan(&others))
			raw := prefix + strings.Repeat("0", bytes-others-overhead) + suffix
			var valid struct {
				V1 struct {
					OnCallNotificationRules []schedule.OnCallNotificationRule
				}
			}
			require.NoError(t, json.Unmarshal([]byte(raw), &valid))
			require.Len(t, valid.V1.OnCallNotificationRules, 1)
			require.Equal(t, 2000, valid.V1.OnCallNotificationRules[0].NextNotification.Year())
			sd8Exec(t, h, `UPDATE schedule_data SET data=$1::jsonb WHERE schedule_id=$2`, raw, sched)
			require.EqualValues(t, bytes, sd8Scalar(t, h, `SELECT sum(octet_length(data::text)) FROM schedule_data`))
			before, audits := smokeUserBusinessState(t, h), smokeDeletionSuccesses(t, h)
			p, err := smokeDeletionPreview(t, h, sd3System(), input)
			if bytes > maxBytes {
				smokeDeletionCode(t, err, ds.DeletionPreviewLimitExceeded)
				require.Nil(t, p)
				ok, err := sd7App(h).Mutation().DeleteAll(sd3System(), input, confirmation)
				smokeDeletionCode(t, err, ds.DeletionUnavailable)
				require.False(t, ok)
				require.Equal(t, before, smokeUserBusinessState(t, h))
				require.Equal(t, audits, smokeDeletionSuccesses(t, h))
			} else {
				require.NoError(t, err)
				require.True(t, p.CanProceed)
				require.True(t, p.Complete)
				ok, err := smokeDeleteAll(t, h, sd7App(h), sd3System(), input)
				require.NoError(t, err)
				require.True(t, ok)
				require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, owner))
				require.Equal(t, audits+1, smokeDeletionSuccesses(t, h))
			}
			t.Logf("NEW LEGAL EQUIVALENT COVERAGE: actual JSON envelope bytes=%d; default 1 MiB budget unchanged; no legacy Audit byte-boundary equivalence claimed", bytes)
		})
	}
	// Dispose the large test-only envelope before background Engine cleanup.
	sd8Exec(t, h, `UPDATE schedule_data SET data='{"V1":{"TemporarySchedules":[],"OnCallNotificationRules":[]}}' WHERE schedule_id=$1`, sched)
}
