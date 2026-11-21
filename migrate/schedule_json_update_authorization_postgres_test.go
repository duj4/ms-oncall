package migrate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

type scheduleJSONNativeFailSigner struct{}

func (scheduleJSONNativeFailSigner) Sign([]byte) ([]byte, error) {
	return nil, errors.New("synthetic signer failure")
}
func (scheduleJSONNativeFailSigner) Verify([]byte, []byte) (bool, bool) { return false, false }

func TestPostgresScheduleJSONUpdateAuthorityAndSigner(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "ScheduleJSONContractTest")
	f, actor, other := newUserPhaseAFixture(t, ctx, db), newUserPhaseAFixture(t, ctx, db), newUserPhaseAFixture(t, ctx, db)
	for _, id := range []any{actor.user, other.user} {
		enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2,organization_role='ORG_ADMIN' WHERE user_id=$1`, id, f.org)
	}
	app := updateNativeApp(t, ctx, db)
	app.ScheduleStore = f.schedules
	app.UserStore = f.users
	id := f.newSchedule(t, ctx)
	temp := userPhaseATemp(f.user)
	require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, id, temp, &f.org))
	human := previewAdmit(t, base, db, actor.user)
	input := map[string]any{"scheduleID": id.String(), "start": temp.Start, "end": temp.End}
	before := scheduleJSONInventory(t, ctx, db, id)
	p, errs := scheduleJSONHTTP(t, human, app, input, true, false)
	require.Empty(t, errs)
	input["confirmation"] = scheduleJSONConfirm(p)
	for _, denied := range []context.Context{previewAdmit(t, base, db, f.user), previewAdmit(t, base, db, newUserPhaseAFixture(t, ctx, db).user)} {
		_, errs := scheduleJSONHTTP(t, denied, app, input, true, false)
		require.NotEmpty(t, errs)
		_, errs = scheduleJSONHTTP(t, denied, app, input, true, true)
		require.NotEmpty(t, errs)
	}
	_, errs = scheduleJSONHTTP(t, previewAdmit(t, base, db, other.user), app, input, true, true)
	require.NotEmpty(t, errs)
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, actor.user)
	_, errs = scheduleJSONHTTP(t, human, app, input, true, true)
	require.NotEmpty(t, errs)
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, actor.user)
	// Re-sign an authentically signed but expired payload with the synthetic key.
	raw, _, ok := strings.Cut(p.ImpactVersion, ".")
	require.True(t, ok)
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	require.NoError(t, err)
	var expired struct {
		Digest string `json:"digest"`
		At     int64  `json:"at"`
	}
	require.NoError(t, json.Unmarshal(payload, &expired))
	expired.At = time.Now().Add(-6 * time.Minute).UnixNano()
	payload, err = json.Marshal(expired)
	require.NoError(t, err)
	sig, err := (previewNativeSigner{}).Sign(append([]byte("goalert.update-induced-deletion.v1\x00schedule-json.v1\x00"), payload...))
	require.NoError(t, err)
	input["confirmation"] = map[string]any{"acknowledgeImpacts": true, "expectedImpactVersion": base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)}
	_, errs = scheduleJSONHTTP(t, human, app, input, true, true)
	require.NotEmpty(t, errs)
	copyApp := *app
	copyApp.PreviewSigner = scheduleJSONNativeFailSigner{}
	_, errs = scheduleJSONHTTP(t, human, &copyApp, input, true, false)
	require.NotEmpty(t, errs)
	require.Equal(t, before, scheduleJSONInventory(t, ctx, db, id))
	p, errs = scheduleJSONHTTP(t, human, app, input, true, false)
	require.Empty(t, errs)
	input["confirmation"] = scheduleJSONConfirm(p)
	_, errs = scheduleJSONHTTP(t, human, app, input, true, true)
	require.Empty(t, errs)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_json_update_audit_events WHERE actor_kind='human' AND actor_id=$1 AND home_organization_id=$2 AND organization_id=$2`, actor.user, f.org))
}

func TestPostgresScheduleJSONUpdatePlatformAdmin(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "ScheduleJSONContractTest")
	for _, home := range []string{"foreign_normal", "default"} {
		t.Run(home, func(t *testing.T) {
			f, actor := newUserPhaseAFixture(t, ctx, db), newUserPhaseAFixture(t, ctx, db)
			enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, actor.user)
			if home == "default" {
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, actor.user, organization.DefaultOrganizationID)
			}
			app := updateNativeApp(t, ctx, db)
			app.ScheduleStore = f.schedules
			app.UserStore = f.users
			id := f.newSchedule(t, ctx)
			temp := userPhaseATemp(f.user)
			require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, id, temp, &f.org))
			human := previewAdmit(t, base, db, actor.user)
			input := map[string]any{"scheduleID": id.String(), "start": temp.Start, "end": temp.End}
			p, errs := scheduleJSONHTTP(t, human, app, input, true, false)
			require.Empty(t, errs)
			input["confirmation"] = scheduleJSONConfirm(p)
			_, errs = scheduleJSONHTTP(t, human, app, input, true, true)
			require.Empty(t, errs)
		})
	}
}
