package migrate

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	riverCorrectnessMigrationID = "20260923133000-fix-river-job-guard.sql"
	riverCorrectnessChecksum    = "54113cfb892166b9881942fac80122384b46da1ed71053e03d88d03149ed89b9"
	riverCorrectnessBundleID    = "ms-oncall-goalert-v035-river-correctness-v1"
)

func TestRiverCorrectnessCanonicalBundle(t *testing.T) {
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	if len(history.entries) != 289 {
		t.Fatalf("canonical count = %d, want 289", len(history.entries))
	}
	entry := history.latest()
	predecessor := history.entries[288-1]
	if entry.Position != 289 || entry.ID != riverCorrectnessMigrationID ||
		entry.OriginalID != riverCorrectnessMigrationID || entry.SHA256 != riverCorrectnessChecksum ||
		entry.BundleID != riverCorrectnessBundleID || entry.Provenance != provenanceMSOnCall ||
		entry.PredecessorID != predecessor.ID {
		t.Fatalf("position-289 identity/provenance = %#v", entry)
	}
	source, err := parseCanonicalSourceBinding(entry.SourceBinding)
	if err != nil {
		t.Fatal(err)
	}
	wantSource := historySourceSpec{
		Kind:                    sourceKindMSOnCallBase,
		Repository:              "https://github.com/duj4/ms-oncall",
		Checkpoint:              "Core GoAlert v0.35.0 PR #4570 River Correctness and Canonical Migration Position 289 V1",
		BaseCommit:              "67e8edbcaf5accaf3f764c35b6bc9f52861e47f5",
		BaseTree:                "dfbd1c4c446fe0d4f03f0516a04ccd74fe8167cd",
		AuthorizationRepository: "https://github.com/duj4/ms-oncall-project",
		AuthorizationCommit:     "089e6e427b49e63782d55fc4cae26804e2dab347",
		AuthorizationTree:       "0f953839d869a454fe472afdee263a2bb96df1be",
	}
	if source != wantSource {
		t.Fatalf("position-289 source = %#v, want %#v", source, wantSource)
	}
	for _, binding := range []string{
		"bundle=goalert-v0.35.0",
		"id=20260911125511-cm-private.sql",
		"sha256=23eafcf4a412ca8dc7484706fd7ca24b9de8dcf1b5b5e8e177e7d7d5b1fa027e",
	} {
		if !strings.Contains(entry.DependencyEvidence, binding) {
			t.Fatalf("position-289 dependency missing %q", binding)
		}
	}
	if entry.AdaptationEvidence != "FORWARD_FIX_OF_TARGET_GOALERT_PR_4570_COMMIT_c24effbaafc1f286b67f7f5de21bb260eab5fd06_BYTE_IDENTICAL_POST_RELEASE_SQL_NOT_V0_35_0_RELEASE_PROVENANCE" {
		t.Fatalf("position-289 adaptation = %q", entry.AdaptationEvidence)
	}
}

// This lab first runs the actual release definition, then upgrades the same
// database and reuses the same physical mutating connection. No Engine worker
// consumes the jobs, so committed business state and durable work can be
// inspected independently.
func TestPostgresRiverCorrectnessUpgradeAndReusedSession(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	var dbName string
	t.Cleanup(func() {
		if dbName == "" {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		admin, err := pgx.Connect(ctx, baseURL)
		if err != nil {
			t.Error(err)
			return
		}
		defer admin.Close(ctx)
		var exists bool
		if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_database WHERE datname = $1)`, dbName).Scan(&exists); err != nil {
			t.Error(err)
		} else if exists {
			t.Errorf("task-owned database %s remains after cleanup", dbName)
		} else {
			t.Logf("cleanup verified: %s absent", dbName)
		}
	})
	// The helper registers its drop after the absence check, so it runs first.
	dbName, testURL := newPostgresTestDatabaseDetails(t, baseURL)
	t.Logf("task-owned database: %s", dbName)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	if count, err := Up(ctx, testURL, history.entries[281-1].Name); err != nil || count != 281 {
		t.Fatalf("empty -> 281 = (%d, %v)", count, err)
	}
	t.Log("empty -> 281: applied 281")
	if count, err := Up(ctx, testURL, history.entries[288-1].Name); err != nil || count != 7 {
		t.Fatalf("281 -> 288 = (%d, %v)", count, err)
	}
	t.Log("281 -> 288: applied 7")
	prefix := *history
	prefix.entries = history.entries[:288]
	before := assertDeterministicProvenanceState(t, ctx, testURL, &prefix)
	if err := VerifyAll(ctx, testURL); err == nil || !strings.Contains(err.Error(), history.latest().Name) {
		t.Fatalf("position-288 VerifyAll = %v, want pending position 289", err)
	}

	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	observer, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(ctx)
	var serverVersion string
	if err := conn.QueryRow(ctx, `SHOW server_version`).Scan(&serverVersion); err != nil {
		t.Fatal(err)
	}
	t.Logf("PostgreSQL %s; reused physical backend PID %d", serverVersion, conn.PgConn().PID())

	orgID, policyID, serviceID, rotationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	insertResourceTestNormalOrganization(t, ctx, observer, orgID, "river-c2")
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO escalation_policies (id, organization_id, name) VALUES ($1, $2, 'River C2 Policy')`, []any{policyID, orgID}},
		{`INSERT INTO services (id, organization_id, escalation_policy_id, name) VALUES ($1, $2, $3, 'River C2 Service')`, []any{serviceID, orgID, policyID}},
		{`INSERT INTO rotations (id, organization_id, name, type, time_zone) VALUES ($1, $2, 'River C2 Rotation', 'daily', 'Etc/UTC')`, []any{rotationID, orgID}},
	} {
		if _, err := observer.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	var alertID int64
	if err := observer.QueryRow(ctx, `INSERT INTO alerts (service_id, summary, dedup_key) VALUES ($1, 'River C2 Alert', 'river-c2') RETURNING id`, serviceID).Scan(&alertID); err != nil {
		t.Fatal(err)
	}
	channels := make([]uuid.UUID, 4)
	for i := range channels {
		channels[i] = uuid.New()
		if _, err := observer.Exec(ctx, `INSERT INTO notification_channels (id, type, name, value) VALUES ($1, 'SLACK', $2, $3)`,
			channels[i], fmt.Sprintf("River C2 Test Channel %d", i), fmt.Sprintf("C2_SYNTHETIC_CHANNEL_%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	// Fixture creation queued a Rotation job on the observer connection.
	if _, err := observer.Exec(ctx, `DELETE FROM river_job`); err != nil {
		t.Fatal(err)
	}
	if _, err := observer.Exec(ctx, `LISTEN "public.river_insert"`); err != nil {
		t.Fatal(err)
	}

	paths := []riverGuardPath{
		{
			name: "direct utility", queue: "c2-river-guard", kind: "c2-river-guard-job", id: uuid.NewString(), argKey: "ID",
			mutate: func(tx pgx.Tx, path riverGuardPath, phase, iteration int) error {
				_, err := tx.Exec(ctx, `SELECT fn_util_river_job($1, $2, $3, jsonb_build_object('ID', $3::text))`, path.queue, path.kind, path.id)
				return err
			},
		},
		{
			name:  "Alert status: trg_track_alert_status_update -> fn_track_alert_status -> fn_util_river_job",
			queue: "status-manager", kind: "status-manager-look-for-work", id: fmt.Sprint(alertID), argKey: "AlertID",
			mutate: func(tx pgx.Tx, _ riverGuardPath, phase, iteration int) error {
				_, err := tx.Exec(ctx, `UPDATE alerts SET status = CASE status WHEN 'triggered' THEN 'active'::enum_alert_status ELSE 'triggered'::enum_alert_status END, summary = $2 WHERE id = $1`,
					alertID, fmt.Sprintf("river-c2-phase-%d-mutation-%d", phase, iteration))
				return err
			},
			verifyMutation: func(phase int) {
				var summary, status string
				if err := observer.QueryRow(ctx, `SELECT summary, status FROM alerts WHERE id = $1`, alertID).Scan(&summary, &status); err != nil {
					t.Fatal(err)
				}
				wantStatus := "triggered"
				if phase%2 == 1 {
					wantStatus = "active"
				}
				if summary != fmt.Sprintf("river-c2-phase-%d-mutation-3", phase) || status != wantStatus {
					t.Fatalf("committed Alert mutation = %q/%q", summary, status)
				}
			},
		},
		{
			name:  "Rotation: trg_track_rotation_updates -> fn_track_rotation_updates -> fn_job_rotation -> fn_util_river_job",
			queue: "rotation-manager", kind: "rotation-manager-update", id: rotationID.String(), argKey: "RotationID",
			mutate: func(tx pgx.Tx, _ riverGuardPath, phase, iteration int) error {
				_, err := tx.Exec(ctx, `UPDATE rotations SET description = $2 WHERE id = $1`, rotationID, fmt.Sprintf("river-c2-phase-%d-mutation-%d", phase, iteration))
				return err
			},
			verifyMutation: func(phase int) {
				var description string
				if err := observer.QueryRow(ctx, `SELECT description FROM rotations WHERE id = $1`, rotationID).Scan(&description); err != nil {
					t.Fatal(err)
				}
				if description != fmt.Sprintf("river-c2-phase-%d-mutation-3", phase) {
					t.Fatalf("committed Rotation mutation = %q", description)
				}
			},
		},
		{
			name:  "Signal: trg_pending_signals_after_insert -> fn_job_signal -> fn_util_river_job",
			queue: "engine-signal-mgr", kind: "signal-manager-schedule-outgoing-messages", id: serviceID.String(), argKey: "ServiceID",
			mutate: func(tx pgx.Tx, _ riverGuardPath, phase, iteration int) error {
				_, err := tx.Exec(ctx, `INSERT INTO pending_signals (service_id, dest_id, params) VALUES ($1, $2, jsonb_build_object('phase', $3::int, 'iteration', $4::int))`,
					serviceID, channels[phase-1], phase, iteration)
				return err
			},
			verifyMutation: func(phase int) {
				var count int
				if err := observer.QueryRow(ctx, `SELECT count(*) FROM pending_signals WHERE service_id = $1`, serviceID).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != phase*3 {
					t.Fatalf("committed Signal count = %d, want %d", count, phase*3)
				}
			},
		},
	}
	for _, path := range paths {
		runRiverGuardTransaction(t, ctx, conn, observer, path, 1, 1, true)
		runRiverGuardTransaction(t, ctx, conn, observer, path, 2, 1, false)
	}

	if count, err := Up(ctx, testURL, ""); err != nil || count != 1 {
		t.Fatalf("288 -> 289 = (%d, %v)", count, err)
	}
	t.Log("288 -> 289: applied 1")
	after := assertDeterministicProvenanceState(t, ctx, testURL, history)
	if !slices.Equal(before, after[:288]) {
		t.Fatal("upgrade changed position 1–288 provenance")
	}
	for _, path := range paths {
		runRiverGuardTransaction(t, ctx, conn, observer, path, 3, 2, true)
		runRiverGuardTransaction(t, ctx, conn, observer, path, 4, 3, true)
	}
	assertRiverGuardIsolationAndRollback(t, ctx, conn, observer)

	var migrationCount, provenanceCount int
	if err := observer.QueryRow(ctx, `SELECT (SELECT count(*) FROM gorp_migrations), (SELECT count(*) FROM ms_oncall_migration_provenance)`).Scan(&migrationCount, &provenanceCount); err != nil {
		t.Fatal(err)
	}
	if migrationCount != 289 || provenanceCount != 289 {
		t.Fatalf("execution/provenance counts = %d/%d, want 289/289", migrationCount, provenanceCount)
	}
	for name, verify := range map[string]func(context.Context, string) error{
		"VerifyAll": VerifyAll, "VerifyIsLatest": VerifyIsLatest,
	} {
		if err := verify(ctx, testURL); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Logf("%s: PASS", name)
	}
	if count, err := Up(ctx, testURL, ""); err != nil || count != 0 {
		t.Fatalf("repeated upgrade = (%d, %v), want no-op", count, err)
	}
	t.Logf("gorp=%d provenance=%d tail=%s; repeated upgrade applied 0", migrationCount, provenanceCount, LatestID())
}

type riverGuardPath struct {
	name, queue, kind, id, argKey string
	mutate                        func(pgx.Tx, riverGuardPath, int, int) error
	verifyMutation                func(int)
}

func runRiverGuardTransaction(t *testing.T, ctx context.Context, conn, observer *pgx.Conn, path riverGuardPath, phase, expectedJobs int, queued bool) {
	t.Helper()
	key := "local.job__" + strings.ReplaceAll(path.queue, "-", "_") + "__" + strings.ReplaceAll(path.id, "-", "_")
	var setting *string
	var isNotNull bool
	if err := conn.QueryRow(ctx, `SELECT current_setting($1, TRUE), current_setting($1, TRUE) IS NOT NULL`, key).Scan(&setting, &isNotNull); err != nil {
		t.Fatal(err)
	}
	if phase == 1 && (setting != nil || isNotNull) {
		t.Fatalf("%s initial guard = %v/%v, want NULL/false", path.name, setting, isNotNull)
	}
	if phase > 1 && (setting == nil || *setting != "" || !isNotNull) {
		t.Fatalf("%s reused guard = %v/%v, want empty string/true", path.name, setting, isNotNull)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func(tx pgx.Tx) { _ = tx.Rollback(ctx) }(tx)
	for iteration := 1; iteration <= 3; iteration++ {
		if err := path.mutate(tx, path, phase, iteration); err != nil {
			t.Fatalf("%s mutation: %v", path.name, err)
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE queue = $1 AND kind = $2 AND args ->> $3 = $4`,
			path.queue, path.kind, path.argKey, path.id).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != expectedJobs {
			t.Fatalf("%s phase %d invocation %d jobs=%d, want %d", path.name, phase, iteration, count, expectedJobs)
		}
	}
	var active string
	if err := tx.QueryRow(ctx, `SELECT current_setting($1, TRUE)`, key).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if queued && active != "true" || !queued && active != "" {
		t.Fatalf("%s active guard = %q, queued=%v", path.name, active, queued)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if path.verifyMutation != nil {
		path.verifyMutation(phase)
	}
	var validJobs int
	if err := observer.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE queue = $1 AND kind = $2 AND args ->> $3 = $4 AND max_attempts = 25 AND priority = 2 AND state = 'available'`,
		path.queue, path.kind, path.argKey, path.id).Scan(&validJobs); err != nil {
		t.Fatal(err)
	}
	if validJobs != expectedJobs {
		t.Fatalf("%s durable jobs/args/attempts/priority = %d, want %d", path.name, validJobs, expectedJobs)
	}
	if err := conn.QueryRow(ctx, `SELECT current_setting($1, TRUE), current_setting($1, TRUE) IS NOT NULL`, key).Scan(&setting, &isNotNull); err != nil {
		t.Fatal(err)
	}
	if setting == nil || *setting != "" || !isNotNull {
		t.Fatalf("%s after COMMIT guard = %v/%v, want empty string/true", path.name, setting, isNotNull)
	}
	if queued {
		notificationCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		notification, err := observer.WaitForNotification(notificationCtx)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]string
		if err := json.Unmarshal([]byte(notification.Payload), &payload); err != nil {
			t.Fatal(err)
		}
		if notification.Channel != "public.river_insert" || payload["queue"] != path.queue || notification.PID != conn.PgConn().PID() {
			t.Fatalf("unexpected notification: %#v", notification)
		}
	}
	t.Logf("%s phase=%d PID=%d: 3 invocations/mutations committed; durable jobs=%d; after COMMIT setting=%q IS NOT NULL=%v; queued=%v",
		path.name, phase, conn.PgConn().PID(), validJobs, *setting, isNotNull, queued)
}

func assertRiverGuardIsolationAndRollback(t *testing.T, ctx context.Context, conn, observer *pgx.Conn) {
	t.Helper()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func(tx pgx.Tx) { _ = tx.Rollback(ctx) }(tx)
	for _, key := range []struct{ queue, kind, id string }{
		{"c2-isolation-a", "c2-kind-a", "sameid"},
		{"c2-isolation-b", "c2-kind-b", "sameid"},
		{"c2-isolation-a", "c2-kind-a", "otherid"},
	} {
		for range 2 {
			if _, err := tx.Exec(ctx, `SELECT fn_util_river_job($1, $2, $3, jsonb_build_object('ID', $3::text))`, key.queue, key.kind, key.id); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := observer.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE queue IN ('c2-isolation-a', 'c2-isolation-b')`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("distinct queues/IDs queued %d jobs, want 3", count)
	}
	tx, err = conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func(tx pgx.Tx) { _ = tx.Rollback(ctx) }(tx)
	if _, err := tx.Exec(ctx, `SELECT fn_util_river_job('c2-rollback', 'c2-rollback-kind', 'rollbackid', '{"ID":"rollbackid"}')`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := observer.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE queue = 'c2-rollback'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rolled-back jobs = (%d, %v), want zero", count, err)
	}
	if _, err := conn.Exec(ctx, `SELECT fn_util_river_job('c2-rollback', 'c2-rollback-kind', 'rollbackid', '{"ID":"rollbackid"}')`); err != nil {
		t.Fatal(err)
	}
	if err := observer.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE queue = 'c2-rollback'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("retry after rollback = (%d, %v), want one", count, err)
	}
	t.Log("queue/ID isolation, preserved kind/args, transaction rollback, and retry: PASS")
}
