package migrate

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestValidateAppliedHistoryAcceptsPreLedgerPrefixesAndDurableProvenance(t *testing.T) {
	history := testAppliedCanonicalHistory(t)

	for appliedCount := 0; appliedCount <= history.provenanceFoundationIndex; appliedCount++ {
		t.Run("pre-ledger-prefix-"+time.Unix(int64(appliedCount), 0).UTC().Format("05"), func(t *testing.T) {
			applied := testAppliedRecords(history, appliedCount)
			got, err := validateAppliedHistory(history, applied, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != appliedCount {
				t.Fatalf("applied count = %d, want %d", got, appliedCount)
			}
		})
	}

	applied := testAppliedRecords(history, len(history.entries))
	provenance := testProvenanceRecords(history, applied)
	got, err := validateAppliedHistory(history, applied, true, provenance)
	if err != nil {
		t.Fatal(err)
	}
	if got != len(history.entries) {
		t.Fatalf("applied count = %d, want %d", got, len(history.entries))
	}
	resolved := resolveCanonicalHistory(history, got)
	for index, entry := range resolved {
		if !entry.Applied {
			t.Fatalf("resolved entry %d (%s) is not applied", index, entry.ID)
		}
	}
}

func TestValidateAppliedHistoryRejectsInvalidGorpState(t *testing.T) {
	history := testAppliedCanonicalHistory(t)
	tests := []struct {
		name    string
		applied func() []appliedMigrationRecord
		wantErr string
	}{
		{
			name: "unknown applied migration",
			applied: func() []appliedMigrationRecord {
				rows := testAppliedRecords(history, 1)
				return append(rows, appliedMigrationRecord{ID: "20249999999999-unknown.sql"})
			},
			wantErr: "unknown applied migration ID",
		},
		{
			name: "missing applied migration gap",
			applied: func() []appliedMigrationRecord {
				rows := testAppliedRecords(history, 3)
				return []appliedMigrationRecord{rows[0], rows[2]}
			},
			wantErr: "history has a gap",
		},
		{
			name: "duplicate applied migration",
			applied: func() []appliedMigrationRecord {
				rows := testAppliedRecords(history, 1)
				return append(rows, rows[0])
			},
			wantErr: "duplicate applied migration ID",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateAppliedHistory(history, test.applied(), false, nil)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateAppliedHistory error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestValidateAppliedHistoryRejectsProvenanceTableContradictions(t *testing.T) {
	history := testAppliedCanonicalHistory(t)
	tests := []struct {
		name          string
		appliedCount  int
		hasProvenance bool
		wantErr       string
	}{
		{
			name:          "Foundation migration applied but table missing",
			appliedCount:  len(history.entries),
			hasProvenance: false,
			wantErr:       "provenance table is missing",
		},
		{
			name:          "table exists before Foundation migration",
			appliedCount:  history.provenanceFoundationIndex,
			hasProvenance: true,
			wantErr:       "provenance table exists before",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			applied := testAppliedRecords(history, test.appliedCount)
			_, err := validateAppliedHistory(history, applied, test.hasProvenance, nil)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateAppliedHistory error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestValidateAppliedHistoryRejectsDurableProvenanceDrift(t *testing.T) {
	history := testAppliedCanonicalHistory(t)
	applied := testAppliedRecords(history, len(history.entries))

	tests := []struct {
		name    string
		mutate  func([]appliedProvenanceRecord) []appliedProvenanceRecord
		wantErr string
	}{
		{
			name: "missing durable provenance",
			mutate: func(rows []appliedProvenanceRecord) []appliedProvenanceRecord {
				return rows[:len(rows)-1]
			},
			wantErr: "provenance count",
		},
		{
			name: "unknown durable provenance",
			mutate: func(rows []appliedProvenanceRecord) []appliedProvenanceRecord {
				rows[0].MigrationID = "20249999999999-unknown.sql"
				return rows
			},
			wantErr: "unknown applied migration provenance ID",
		},
		{
			name: "duplicate durable position",
			mutate: func(rows []appliedProvenanceRecord) []appliedProvenanceRecord {
				rows[1].CanonicalPosition = rows[0].CanonicalPosition
				return rows
			},
			wantErr: "duplicate applied migration provenance position",
		},
		{
			name: "canonical order divergence",
			mutate: func(rows []appliedProvenanceRecord) []appliedProvenanceRecord {
				rows[1].CanonicalPosition, rows[2].CanonicalPosition = rows[2].CanonicalPosition, rows[1].CanonicalPosition
				return rows
			},
			wantErr: "field canonical_position",
		},
		{
			name: "checksum disagreement",
			mutate: func(rows []appliedProvenanceRecord) []appliedProvenanceRecord {
				rows[0].ContentSHA256 = strings.Repeat("f", 64)
				return rows
			},
			wantErr: "field content_sha256",
		},
		{
			name: "provenance disagreement",
			mutate: func(rows []appliedProvenanceRecord) []appliedProvenanceRecord {
				rows[0].ProvenanceClass = provenanceMSOnCall
				return rows
			},
			wantErr: "field provenance_class",
		},
		{
			name: "source disagreement",
			mutate: func(rows []appliedProvenanceRecord) []appliedProvenanceRecord {
				rows[0].SourceBinding = "changed"
				return rows
			},
			wantErr: "field source_binding",
		},
		{
			name: "predecessor disagreement",
			mutate: func(rows []appliedProvenanceRecord) []appliedProvenanceRecord {
				rows[1].PredecessorID = sql.NullString{String: "wrong", Valid: true}
				return rows
			},
			wantErr: "field predecessor_migration_id",
		},
		{
			name: "invalid record origin",
			mutate: func(rows []appliedProvenanceRecord) []appliedProvenanceRecord {
				rows[0].RecordOrigin = "UNKNOWN"
				return rows
			},
			wantErr: "expected PRE_LEDGER_BOOTSTRAP",
		},
		{
			name: "pre-ledger migration incorrectly claims canonical execution",
			mutate: func(rows []appliedProvenanceRecord) []appliedProvenanceRecord {
				rows[0].RecordOrigin = recordOriginCanonical
				return rows
			},
			wantErr: "expected PRE_LEDGER_BOOTSTRAP",
		},
		{
			name: "Foundation migration incorrectly claims pre-ledger bootstrap",
			mutate: func(rows []appliedProvenanceRecord) []appliedProvenanceRecord {
				rows[history.provenanceFoundationIndex].RecordOrigin = recordOriginPreLedgerBootstrap
				return rows
			},
			wantErr: "expected CANONICAL_EXECUTION",
		},
		{
			name: "post-Foundation migration incorrectly claims pre-ledger bootstrap",
			mutate: func(rows []appliedProvenanceRecord) []appliedProvenanceRecord {
				rows[history.provenanceFoundationIndex+1].RecordOrigin = recordOriginPreLedgerBootstrap
				return rows
			},
			wantErr: "expected CANONICAL_EXECUTION",
		},
		{
			name: "applied timestamp disagreement",
			mutate: func(rows []appliedProvenanceRecord) []appliedProvenanceRecord {
				rows[0].AppliedAt.Time = rows[0].AppliedAt.Time.Add(time.Second)
				return rows
			},
			wantErr: "field applied_at",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rows := testProvenanceRecords(history, applied)
			rows = test.mutate(rows)
			_, err := validateAppliedHistory(history, applied, true, rows)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateAppliedHistory error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestExpectedRecordOriginUsesManifestFoundationBoundary(t *testing.T) {
	history := testAppliedCanonicalHistory(t)
	want := []string{
		recordOriginPreLedgerBootstrap,
		recordOriginPreLedgerBootstrap,
		recordOriginCanonical,
		recordOriginCanonical,
	}
	for index, expected := range want {
		got, err := expectedRecordOrigin(history, index)
		if err != nil {
			t.Fatal(err)
		}
		if got != expected {
			t.Fatalf("origin at canonical index %d = %q, want %q", index, got, expected)
		}
	}

	for _, invalidIndex := range []int{-1, len(history.entries)} {
		invalid := *history
		invalid.provenanceFoundationIndex = invalidIndex
		if _, err := expectedRecordOrigin(&invalid, 0); err == nil || !strings.Contains(err.Error(), "no unambiguous provenance Foundation boundary") {
			t.Fatalf("invalid Foundation boundary %d error = %v", invalidIndex, err)
		}
		if _, err := validateAppliedHistory(&invalid, nil, false, nil); err == nil || !strings.Contains(err.Error(), "no unambiguous provenance Foundation boundary") {
			t.Fatalf("validateAppliedHistory invalid Foundation boundary %d error = %v", invalidIndex, err)
		}
	}
}

func TestDivergentHistoryIsRejectedBeforeRollbackPlanning(t *testing.T) {
	history := testAppliedCanonicalHistory(t)
	applied := testAppliedRecords(history, len(history.entries))
	applied = []appliedMigrationRecord{applied[0], applied[2]}

	if _, err := validateAppliedHistory(history, applied, false, nil); err == nil {
		t.Fatal("divergent history was accepted before rollback planning")
	}
}

func testAppliedCanonicalHistory(t *testing.T) *canonicalHistory {
	t.Helper()
	fixture := newHistoryFixture(
		t,
		"20240101000000-upstream-one.sql",
		"20240102000000-upstream-two.sql",
		"20240103000000-provenance-foundation.sql",
	)
	fixture.splitSecondEntryIntoBundle(t)
	foundationID := fixture.manifest.Bundles[1].Entries[0].ID
	fixture.manifest.ProvenanceFoundationMigrationID = foundationID
	futureID := "20240104000000-ms-oncall-future.sql"
	futureSQL := []byte("-- +migrate Up\nSELECT 4;\n-- +migrate Down\n")
	fixture.files[futureID] = futureSQL
	foundationEntry := fixture.manifest.Bundles[1].Entries[0]
	fixture.manifest.Bundles = append(fixture.manifest.Bundles, historyBundleSpec{
		ID:            "ms-oncall-test-future",
		FirstPosition: 4,
		Provenance:    provenanceMSOnCall,
		Source: historySourceSpec{
			Kind:                    sourceKindMSOnCallBase,
			Repository:              "https://example.invalid/ms-oncall",
			Checkpoint:              "test-future-checkpoint",
			BaseCommit:              strings.Repeat("5", 40),
			BaseTree:                strings.Repeat("6", 40),
			AuthorizationRepository: "https://example.invalid/ms-oncall-project",
			AuthorizationCommit:     strings.Repeat("7", 40),
			AuthorizationTree:       strings.Repeat("8", 40),
		},
		DependsOn: &historyDependencySpec{
			BundleID:    fixture.manifest.Bundles[1].ID,
			MigrationID: foundationEntry.ID,
			SHA256:      foundationEntry.SHA256,
			Evidence:    "TEST_APPEND_AFTER_FOUNDATION",
		},
		AdaptationEvidence: "NOT_APPLICABLE_TEST_FUTURE",
		Entries: []historyEntrySpec{{
			ID:         futureID,
			OriginalID: futureID,
			SHA256:     fmt.Sprintf("%x", sha256.Sum256(futureSQL)),
		}},
	})
	fixture.manifest.Bundles[0].Provenance = provenanceUpstream
	fixture.manifest.Bundles[0].Source = historySourceSpec{
		Kind:       sourceKindGoAlertRelease,
		Repository: "https://example.invalid/goalert",
		Release:    "v0.test",
		Commit:     strings.Repeat("a", 40),
	}
	history, err := loadCanonicalHistory(fixture.fsys(t))
	if err != nil {
		t.Fatal(err)
	}
	return history
}

func testAppliedRecords(history *canonicalHistory, count int) []appliedMigrationRecord {
	records := make([]appliedMigrationRecord, count)
	for index := range records {
		records[index] = appliedMigrationRecord{
			ID: history.entries[index].ID,
			AppliedAt: sql.NullTime{
				Time:  time.Unix(int64(index+1), 0).UTC(),
				Valid: true,
			},
		}
	}
	return records
}

func testProvenanceRecords(history *canonicalHistory, applied []appliedMigrationRecord) []appliedProvenanceRecord {
	appliedByID := make(map[string]appliedMigrationRecord, len(applied))
	for _, record := range applied {
		appliedByID[record.ID] = record
	}
	records := make([]appliedProvenanceRecord, len(applied))
	for index := range records {
		entry := history.entries[index]
		origin, err := expectedRecordOrigin(history, index)
		if err != nil {
			panic(err)
		}
		records[index] = appliedProvenanceRecord{
			CanonicalPosition:   entry.Position,
			MigrationID:         entry.ID,
			MigrationName:       entry.Name,
			ProvenanceClass:     entry.Provenance,
			OriginalMigrationID: entry.OriginalID,
			ContentSHA256:       entry.SHA256,
			SourceBinding:       entry.SourceBinding,
			BundleID:            entry.BundleID,
			PredecessorID: sql.NullString{
				String: entry.PredecessorID,
				Valid:  entry.PredecessorID != "",
			},
			DependencyEvidence: entry.DependencyEvidence,
			AdaptationEvidence: entry.AdaptationEvidence,
			RecordOrigin:       origin,
			AppliedAt:          appliedByID[entry.ID].AppliedAt,
		}
	}
	return records
}
