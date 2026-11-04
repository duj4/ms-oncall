package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/limit"
	"github.com/target/goalert/test/smoke/harness"
)

// Both oracles read persisted PG columns; neither derives effects from input.
func rotationActualProjection(t *testing.T, h *harness.Harness, id string) string {
	t.Helper()
	var result string
	require.NoError(t, h.App().DB().QueryRow(`SELECT jsonb_build_object(
 'participants',coalesce((SELECT jsonb_agg(jsonb_build_object('id',id,'user',user_id,'position',position) ORDER BY position) FROM rotation_participants WHERE rotation_id=$1),'[]'),
 'count',(SELECT participant_count FROM rotations WHERE id=$1),
 'state',(SELECT jsonb_build_object('id',id,'position',position,'participant',rotation_participant_id,'start',shift_start,'version',version) FROM rotation_state WHERE rotation_id=$1))::text`, id).Scan(&result))
	return result
}

func rotationSavedProjection(t *testing.T, h *harness.Harness, id, side string) string {
	t.Helper()
	require.Contains(t, []string{"before", "after"}, side)
	var result string
	q := fmt.Sprintf(`SELECT jsonb_build_object(
 'participants',coalesce((SELECT jsonb_agg(jsonb_build_object('id',p.id,'user',p.uid,'position',p.pos) ORDER BY p.ord) FROM unnest(%[1]s_participant_ids,%[1]s_user_ids,%[1]s_positions) WITH ORDINALITY p(id,uid,pos,ord)),'[]'),
 'count',%[1]s_participant_count,
 'state',CASE WHEN %[1]s_state_id IS NULL THEN NULL ELSE jsonb_build_object('id',%[1]s_state_id,'position',%[1]s_state_position,'participant',%[1]s_state_participant_id,'start',%[1]s_shift_start,'version',%[1]s_state_version) END)::text
 FROM schedule_rotation_update_audit_events WHERE target_id=$1 AND outcome='committed' ORDER BY occurred_at DESC LIMIT 1`, side)
	require.NoError(t, h.App().DB().QueryRow(q, id).Scan(&result))
	return result
}

func rotationEffectEvidence(t *testing.T, label string, v any) {
	t.Helper()
	if dir := os.Getenv("ROTATION_UPDATE_AUDIT_EVIDENCE"); dir != "" {
		b, err := json.MarshalIndent(v, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "-")+"-"+label+".json"), append(b, '\n'), 0600))
	}
}

func rotationEffectUpdate(t *testing.T, h *harness.Harness, fields string, mask int, users []string) {
	t.Helper()
	id := h.UUID("rotation-a")
	before := rotationActualProjection(t, h, id)
	n := rotationAuditCount(t, h)
	h.FastForward(time.Second)
	r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateRotation(input:{id:%q,%s})}`, id, fields))
	require.Empty(t, r.Errors)
	require.JSONEq(t, `{"updateRotation":true}`, string(r.Data))
	require.Equal(t, n+1, rotationAuditCount(t, h))
	after := rotationActualProjection(t, h, id)
	require.JSONEq(t, before, rotationSavedProjection(t, h, id, "before"))
	require.JSONEq(t, after, rotationSavedProjection(t, h, id, "after"))
	var actualMask int
	var scalar bool
	require.NoError(t, h.App().DB().QueryRow(`SELECT requested_fields,rotation_row_written FROM schedule_rotation_update_audit_events WHERE target_id=$1 ORDER BY occurred_at DESC LIMIT 1`, id).Scan(&actualMask, &scalar))
	require.Equal(t, mask, actualMask)
	require.Equal(t, mask&63 != 0, scalar)
	if mask == 0 {
		require.JSONEq(t, before, after)
	}
	if users != nil {
		var actual string
		require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(user_id ORDER BY position),'[]')::text FROM rotation_participants WHERE rotation_id=$1`, id).Scan(&actual))
		b, err := json.Marshal(users)
		require.NoError(t, err)
		require.JSONEq(t, string(b), actual)
	}
	rotationEffectEvidence(t, fmt.Sprintf("effect-%d", n), map[string]any{"mask": mask, "scalar_row_written": scalar, "before": json.RawMessage(before), "after": json.RawMessage(after)})
}

func TestRotationUpdateAuditAllFieldsAndParticipantEffects(t *testing.T) {
	h := rotationAuditHarness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	a, b, c := h.UUID("user-a"), h.UUID("user-b"), h.UUID("user-c")
	for _, tc := range []struct {
		fields string
		mask   int
		users  []string
	}{
		{"", 0, nil}, {`name:"Actual scalar witness"`, 1, nil}, {`description:"Synthetic effect description"`, 2, nil},
		{`start:"2026-11-04T01:00:00Z"`, 4, nil}, {`type:hourly`, 8, nil}, {`shiftLength:2`, 16, nil}, {`timeZone:"Asia/Shanghai"`, 32, nil},
		{fmt.Sprintf(`userIDs:[%q,%q]`, a, b), 64, []string{a, b}}, {`activeUserIndex:1`, 128, nil},
		{fmt.Sprintf(`name:"Combined rotation",description:"Combined synthetic",start:"2026-11-04T02:00:00Z",type:daily,shiftLength:1,timeZone:"Etc/UTC",userIDs:[%q,%q,%q],activeUserIndex:2`, a, b, c), 255, []string{a, b, c}},
		{fmt.Sprintf(`userIDs:[%q,%q,%q]`, c, a, b), 64, []string{c, a, b}},
		{fmt.Sprintf(`userIDs:[%q,%q]`, b, c), 64, []string{b, c}},
		{fmt.Sprintf(`userIDs:[%q,%q]`, b, b), 64, []string{b, b}},
		{`userIDs:[],activeUserIndex:0`, 192, []string{}},
		{`activeUserIndex:99`, 128, nil}, // Existing no-state UPDATE affects zero rows.
		{fmt.Sprintf(`userIDs:[%q]`, a), 64, []string{a}},
	} {
		rotationEffectUpdate(t, h, tc.fields, tc.mask, tc.users)
	}
	for _, fields := range []string{`activeUserIndex:-1`, `activeUserIndex:5`, `shiftLength:-1`, `timeZone:"SYNTHETIC_BAD_ZONE"`, `userIDs:["invalid"]`, fmt.Sprintf(`userIDs:[%q]`, h.UUID("missing-user"))} {
		before := rotationActualProjection(t, h, h.UUID("rotation-a"))
		r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateRotation(input:{id:%q,%s})}`, h.UUID("rotation-a"), fields))
		require.NotEmpty(t, r.Errors)
		require.JSONEq(t, before, rotationActualProjection(t, h, h.UUID("rotation-a")))
	}
	h.SetSystemLimit(limit.ParticipantsPerRotation, 1)
	r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateRotation(input:{id:%q,userIDs:[%q,%q]})}`, h.UUID("rotation-a"), a, b))
	require.NotEmpty(t, r.Errors)
	require.Contains(t, fmt.Sprint(r.Errors), "too many participants")
	rotationAuditRows(t, h)
}

func TestRotationUpdateAuditIntermediateWriteFailure(t *testing.T) {
	h := rotationAuditHarness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	for _, part := range []bool{true, false} {
		function, table := "c6_part_fail", "rotation_participants"
		condition := fmt.Sprintf("NEW.user_id='%s'::uuid", h.UUID("user-c"))
		fields := fmt.Sprintf(`description:"Must rollback partial participant writes",userIDs:[%q,%q]`, h.UUID("user-b"), h.UUID("user-c"))
		if !part {
			function, table = "c6_state_fail", "rotation_state"
			condition = "NEW.position <> OLD.position"
			fields = `description:"Must rollback state write",activeUserIndex:1`
		}
		_, err := h.App().DB().Exec(fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF %s THEN RAISE EXCEPTION USING MESSAGE='SYNTHETIC_NTH_WRITE_SECRET',DETAIL='SYNTHETIC_SQL_DETAIL'; END IF; RETURN NEW; END $$; CREATE TRIGGER c6_write_fail BEFORE UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, function, condition, table, function))
		require.NoError(t, err)
		before := serviceManagementSnapshot(t, h)
		wait := h.ExpectBackendError("rotation.update transaction failed")
		r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateRotation(input:{id:%q,%s})}`, h.UUID("rotation-a"), fields))
		wait()
		require.NotEmpty(t, r.Errors)
		require.Equal(t, before, serviceManagementSnapshot(t, h))
		var n int
		require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM schedule_rotation_update_audit_events WHERE outcome='committed'`).Scan(&n))
		require.Zero(t, n)
		_, err = h.App().DB().Exec(fmt.Sprintf(`DROP TRIGGER c6_write_fail ON %s; DROP FUNCTION %s()`, table, function))
		require.NoError(t, err)
	}
	rotationAuditRows(t, h)
}

func TestRotationUpdateAuditHistoricalForeignUserAndTransfer(t *testing.T) {
	h := rotationAuditHarness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	id := h.UUID("rotation-a")
	// Actual admission validation ran before this barrier. UOA has no transfer
	// lock/fence; this test explicitly preserves that accepted D08 boundary.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	gate, err := h.App().DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = gate.Rollback() }()
	var blocker int
	require.NoError(t, gate.QueryRow(`SELECT pg_backend_pid()`).Scan(&blocker))
	_, err = gate.Exec(`LOCK schedule_rotation_update_audit_events IN SHARE MODE`)
	require.NoError(t, err)
	done := make(chan *stepOrganizationResponse, 1)
	defer func() {
		_ = gate.Rollback()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("request did not release")
		}
	}()
	go func() {
		done <- stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateRotation(input:{id:%q,userIDs:[%q,%q]})}`, id, h.UUID("user-a"), h.UUID("user-b")))
	}()
	require.Eventually(t, func() bool {
		var n int
		e := h.App().DB().QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, blocker).Scan(&n)
		return e == nil && n == 1
	}, 5*time.Second, 10*time.Millisecond)
	_, err = h.App().DB().ExecContext(ctx, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, h.UUID("user-b"), h.UUID("org-b"))
	require.NoError(t, err)
	require.NoError(t, gate.Rollback())
	r := <-done
	require.Empty(t, r.Errors)
	done <- nil
	actual := rotationActualProjection(t, h, id)
	require.JSONEq(t, actual, rotationSavedProjection(t, h, id, "after"))
	rotationEffectUpdate(t, h, `description:"Historical foreign relation remains"`, 2, nil)
	rotationEffectUpdate(t, h, `activeUserIndex:1`, 128, nil)
	before := serviceManagementSnapshot(t, h)
	r = stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateRotation(input:{id:%q,userIDs:[%q,%q]})}`, id, h.UUID("user-b"), h.UUID("user-a")))
	require.NotEmpty(t, r.Errors, "existing complete-list foreign validation is preserved")
	require.Equal(t, before, serviceManagementSnapshot(t, h))
	var org string
	require.NoError(t, h.App().DB().QueryRow(`SELECT target_organization_id FROM schedule_rotation_update_audit_events WHERE outcome='committed' ORDER BY occurred_at DESC LIMIT 1`).Scan(&org))
	require.Equal(t, harness.SmokeOrganizationID, org, "related User transfer never changes the actual modified Rotation's organization")
	rotationAuditRows(t, h)
}

func TestRotationUpdateAuditFragmentAndConcurrentRoots(t *testing.T) {
	h := rotationAuditHarness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation FragmentPatch{...RotationPatch} fragment RotationPatch on Mutation{fragmentAlias:updateRotation(input:{id:%q,description:"Fragment patch"})}`, h.UUID("rotation-a")))
	require.Empty(t, r.Errors)
	// Production permits one concurrent request per SourceInfo. Use distinct
	// real signed Sessions for the same admitted actor; do not bypass middleware.
	tokens := make([]string, 3)
	for i := range tokens {
		tok, err := h.App().AuthHandler.CreateSession(context.Background(), "goalert-smoketest", h.UUID("user-a"))
		require.NoError(t, err)
		tokens[i], err = tok.Encode(h.App().SessionKeyring.Sign)
		require.NoError(t, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	gate, err := h.App().DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	var blocker int
	require.NoError(t, gate.QueryRow(`SELECT pg_backend_pid()`).Scan(&blocker))
	_, err = gate.Exec(`LOCK schedule_rotation_update_audit_events IN SHARE MODE`)
	require.NoError(t, err)
	done := make(chan *stepOrganizationResponse, 3)
	defer func() {
		_ = gate.Rollback()
		for i := 0; i < 3; i++ {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("concurrent request did not release")
			}
		}
	}()
	go func() {
		done <- stepOrganizationPost(t, h, map[string]any{"query": fmt.Sprintf(`mutation{updateRotation(input:{id:%q,description:"First concurrent"})}`, h.UUID("rotation-a"))}, tokens[0], false)
	}()

	var owner int
	require.Eventually(t, func() bool {
		e := h.App().DB().QueryRowContext(ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, blocker).Scan(&owner)
		return e == nil
	}, 5*time.Second, 10*time.Millisecond)
	for i, id := range []string{h.UUID("rotation-a"), h.UUID("rotation-c")} {
		go func(id, token string) {
			done <- stepOrganizationPost(t, h, map[string]any{"query": fmt.Sprintf(`mutation{updateRotation(input:{id:%q,description:"Queued concurrent"})}`, id)}, token, false)
		}(id, tokens[i+1])
	}

	observed := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		e := h.App().DB().QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, owner).Scan(&n)
		if e == nil && n >= 1 {
			observed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	var chain string
	require.NoError(t, h.App().DB().QueryRowContext(ctx, `SELECT jsonb_agg(jsonb_build_object('pid',pid,'state',state,'wait_event_type',wait_event_type,'wait_event',wait_event,'blockers',pg_blocking_pids(pid)))::text FROM pg_stat_activity WHERE datname=current_database()`).Scan(&chain))
	rotationEffectEvidence(t, "bounded-concurrent-chain", map[string]any{"chain": json.RawMessage(chain), "pool": h.App().DB().Stats(), "new_lock_policy": false, "owner": owner, "gate": blocker, "expected_wait_observed": observed})
	require.NoError(t, gate.Rollback())
	for i := 0; i < 3; i++ {
		r := <-done
		require.Empty(t, r.Errors)
	}
	for i := 0; i < 3; i++ {
		done <- nil
	}
	var n int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM schedule_rotation_update_audit_events WHERE outcome='committed'`).Scan(&n))
	require.Equal(t, 4, n)
	require.True(t, observed, "inspect saved chain/pool before interpreting the wait")
	rotationAuditRows(t, h)
}
