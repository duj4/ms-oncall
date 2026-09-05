package migrate

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func TestEmbeddedCanonicalHistory(t *testing.T) {
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(history.entries), 279; got != want {
		t.Fatalf("canonical entry count = %d, want %d", got, want)
	}
	if got, want := history.provenanceFoundationIndex, 274; got != want {
		t.Fatalf("provenance Foundation index = %d, want %d", got, want)
	}
	for _, entry := range history.entries[:history.provenanceFoundationIndex] {
		if entry.Provenance != provenanceUpstream {
			t.Fatalf("historical migration %q provenance = %q, want %q", entry.ID, entry.Provenance, provenanceUpstream)
		}
		if !strings.Contains(entry.SourceBinding, "0918387e38650aaddd6a923d445ee992f64d6ab6") {
			t.Fatalf("historical migration %q is not bound to adopted GoAlert v0.34.1 commit", entry.ID)
		}
	}
	foundation := history.entries[history.provenanceFoundationIndex]
	if foundation.ID != "20260830195814-ms-oncall-migration-provenance.sql" {
		t.Fatalf("provenance Foundation migration = %q", foundation.ID)
	}
	if foundation.Provenance != provenanceMSOnCall {
		t.Fatalf("Foundation migration provenance = %q, want %q", foundation.Provenance, provenanceMSOnCall)
	}
	if !strings.Contains(foundation.SourceBinding, "e4f097077c15f6e6ae0fa2e5fc3d61938e295970") ||
		!strings.Contains(foundation.SourceBinding, "7cc13bed88ba5483ab1f60e4a9628ff8261569c6") ||
		!strings.Contains(foundation.SourceBinding, "0a9ba1131988608ffdc7a4faa9cdf72ea6ccc74b") ||
		!strings.Contains(foundation.SourceBinding, "e3c20a00455d0c6bd247e8c547bd658eaf5b6c41") {
		t.Fatalf("MS OnCall foundation source binding does not contain the exact parent commit and tree: %s", foundation.SourceBinding)
	}

	organizationFoundation := history.entries[len(history.entries)-4]
	if organizationFoundation.Position != 276 || organizationFoundation.ID != "20260901100808-ms-oncall-organization-persistence.sql" {
		t.Fatalf("Organization persistence migration = position %d, ID %q", organizationFoundation.Position, organizationFoundation.ID)
	}
	if organizationFoundation.Provenance != provenanceMSOnCall || organizationFoundation.BundleID != "ms-oncall-organization-default-persistence-foundation-v1" {
		t.Fatalf("Organization persistence provenance/bundle = %q/%q", organizationFoundation.Provenance, organizationFoundation.BundleID)
	}
	if organizationFoundation.OriginalID != organizationFoundation.ID || organizationFoundation.SHA256 != "4551270e716d9dd6572dbde7173b6d7a15a3510f11045e770d5f51c80dbfdc5f" {
		t.Fatalf("Organization persistence original identity/checksum = %q/%q", organizationFoundation.OriginalID, organizationFoundation.SHA256)
	}
	if organizationFoundation.PredecessorID != foundation.ID ||
		!strings.Contains(organizationFoundation.DependencyEvidence, "bundle=ms-oncall-migration-provenance-history-foundation-v1") ||
		!strings.Contains(organizationFoundation.DependencyEvidence, "id=20260830195814-ms-oncall-migration-provenance.sql") ||
		!strings.Contains(organizationFoundation.DependencyEvidence, "sha256=c22fb8e6bd4fe90788d5c0f6b9dd8ecb4cce43658ffa79691311c3846df0db5e") ||
		!strings.Contains(organizationFoundation.DependencyEvidence, "APPEND_AFTER_ACCEPTED_MIGRATION_PROVENANCE_AND_COMBINED_HISTORY_FOUNDATION_V1") {
		t.Fatalf("Organization persistence dependency evidence is incomplete: %s", organizationFoundation.DependencyEvidence)
	}
	if organizationFoundation.AdaptationEvidence != "ADDITIVE_MS_ONCALL_ORGANIZATION_PERSISTENCE_FOUNDATION_NOT_AN_UPSTREAM_MIGRATION" {
		t.Fatalf("Organization persistence adaptation evidence = %q", organizationFoundation.AdaptationEvidence)
	}
	for _, value := range []string{
		"53393ce48da36c2185c36b92ac5393f8658bf7e7",
		"c7bbe26f003a286d9fe162a4313d4d9acff874ec",
		"83ce1e292f6db1cbb6d89287a1614fd14cada482",
		"1c7950b46e50fdf31eeb2cbaf04c98205237fe68",
	} {
		if !strings.Contains(organizationFoundation.SourceBinding, value) {
			t.Fatalf("Organization persistence source binding is missing %q: %s", value, organizationFoundation.SourceBinding)
		}
	}

	assignmentFoundation := history.entries[len(history.entries)-3]
	if assignmentFoundation.Position != 277 || assignmentFoundation.ID != "20260901220323-ms-oncall-user-organization-assignment-persistence.sql" {
		t.Fatalf("UserOrganizationAssignment persistence migration = position %d, ID %q", assignmentFoundation.Position, assignmentFoundation.ID)
	}
	if assignmentFoundation.Provenance != provenanceMSOnCall || assignmentFoundation.BundleID != "ms-oncall-user-organization-assignment-persistence-foundation-v1" {
		t.Fatalf("UserOrganizationAssignment persistence provenance/bundle = %q/%q", assignmentFoundation.Provenance, assignmentFoundation.BundleID)
	}
	if assignmentFoundation.OriginalID != assignmentFoundation.ID || assignmentFoundation.SHA256 != "b9bbade729665431c23c74c689aa90f1c0ba484678026b6a6398b649f0e21b8e" {
		t.Fatalf("UserOrganizationAssignment persistence original identity/checksum = %q/%q", assignmentFoundation.OriginalID, assignmentFoundation.SHA256)
	}
	if assignmentFoundation.PredecessorID != organizationFoundation.ID ||
		!strings.Contains(assignmentFoundation.DependencyEvidence, "bundle=ms-oncall-organization-default-persistence-foundation-v1") ||
		!strings.Contains(assignmentFoundation.DependencyEvidence, "id=20260901100808-ms-oncall-organization-persistence.sql") ||
		!strings.Contains(assignmentFoundation.DependencyEvidence, "sha256=4551270e716d9dd6572dbde7173b6d7a15a3510f11045e770d5f51c80dbfdc5f") ||
		!strings.Contains(assignmentFoundation.DependencyEvidence, "APPEND_AFTER_ACCEPTED_ORGANIZATION_DEFAULT_PERSISTENCE_FOUNDATION_V1") {
		t.Fatalf("UserOrganizationAssignment persistence dependency evidence is incomplete: %s", assignmentFoundation.DependencyEvidence)
	}
	if assignmentFoundation.AdaptationEvidence != "ADDITIVE_MS_ONCALL_USER_ORGANIZATION_ASSIGNMENT_PERSISTENCE_FOUNDATION_NOT_AN_UPSTREAM_MIGRATION" {
		t.Fatalf("UserOrganizationAssignment persistence adaptation evidence = %q", assignmentFoundation.AdaptationEvidence)
	}
	for _, value := range []string{
		"7e698840ee69eb04c84e19830221b4637be435c6",
		"4c2d01c2cdf2785a78d423e0b32258c9b6d7a212",
		"de12830b9c2da4c4a2d71020cf4374f76cfdb7cf",
		"22aa6f10bb7fe3cbea306a250513e48caec50335",
	} {
		if !strings.Contains(assignmentFoundation.SourceBinding, value) {
			t.Fatalf("UserOrganizationAssignment persistence source binding is missing %q: %s", value, assignmentFoundation.SourceBinding)
		}
	}

	humanSecurityFoundation := history.entries[len(history.entries)-2]
	if humanSecurityFoundation.Position != 278 || humanSecurityFoundation.ID != "20260903184951-ms-oncall-human-security-generation-persistence.sql" {
		t.Fatalf("human security generation migration = position %d, ID %q", humanSecurityFoundation.Position, humanSecurityFoundation.ID)
	}
	if humanSecurityFoundation.Provenance != provenanceMSOnCall || humanSecurityFoundation.BundleID != "ms-oncall-human-security-generation-persistence-foundation-v1" {
		t.Fatalf("human security generation provenance/bundle = %q/%q", humanSecurityFoundation.Provenance, humanSecurityFoundation.BundleID)
	}
	if humanSecurityFoundation.OriginalID != humanSecurityFoundation.ID || humanSecurityFoundation.SHA256 != "442b919a8b001b9cf6ea1a118b0a5ebe7d6b674483ca867e1c264efb7e854d16" {
		t.Fatalf("human security generation original identity/checksum = %q/%q", humanSecurityFoundation.OriginalID, humanSecurityFoundation.SHA256)
	}
	if humanSecurityFoundation.PredecessorID != assignmentFoundation.ID ||
		!strings.Contains(humanSecurityFoundation.DependencyEvidence, "bundle=ms-oncall-user-organization-assignment-persistence-foundation-v1") ||
		!strings.Contains(humanSecurityFoundation.DependencyEvidence, "id=20260901220323-ms-oncall-user-organization-assignment-persistence.sql") ||
		!strings.Contains(humanSecurityFoundation.DependencyEvidence, "sha256=b9bbade729665431c23c74c689aa90f1c0ba484678026b6a6398b649f0e21b8e") ||
		!strings.Contains(humanSecurityFoundation.DependencyEvidence, "APPEND_AFTER_ACCEPTED_USER_ORGANIZATION_ASSIGNMENT_PERSISTENCE_FOUNDATION_V1") {
		t.Fatalf("human security generation dependency evidence is incomplete: %s", humanSecurityFoundation.DependencyEvidence)
	}
	if humanSecurityFoundation.AdaptationEvidence != "ADDITIVE_MS_ONCALL_HUMAN_SECURITY_GENERATION_PERSISTENCE_FOUNDATION_NOT_AN_UPSTREAM_MIGRATION" {
		t.Fatalf("human security generation adaptation evidence = %q", humanSecurityFoundation.AdaptationEvidence)
	}
	for _, value := range []string{
		"bbdaebfe27a74643e8cdd03d27845ff76e69771b",
		"364ad3fa042b186c3e32b3ee3e4bc25f529c925e",
		"3a7bd58b9d1a3c5e866b402f6600e9e416ae2705",
		"588b843dd81fb81cdd2ce2aa3e30464bfdb05e10",
	} {
		if !strings.Contains(humanSecurityFoundation.SourceBinding, value) {
			t.Fatalf("human security generation source binding is missing %q: %s", value, humanSecurityFoundation.SourceBinding)
		}
	}

	latest := history.latest()
	if latest.Position != 279 || latest.ID != "20260905230921-ms-oncall-session-generation-binding-human-security-generation-retirement-cleanup-v1.sql" {
		t.Fatalf("latest canonical migration = position %d, ID %q", latest.Position, latest.ID)
	}
	if latest.Provenance != provenanceMSOnCall || latest.BundleID != "ms-oncall-session-generation-binding-human-security-generation-retirement-cleanup-v1" {
		t.Fatalf("generation retirement provenance/bundle = %q/%q", latest.Provenance, latest.BundleID)
	}
	if latest.OriginalID != latest.ID || latest.SHA256 != "14b6dc8797bf8a55ccc0d35737dbdafe698c9da601693ac2d651057a7c7aaf5f" {
		t.Fatalf("generation retirement original identity/checksum = %q/%q", latest.OriginalID, latest.SHA256)
	}
	if latest.PredecessorID != humanSecurityFoundation.ID ||
		!strings.Contains(latest.DependencyEvidence, "bundle=ms-oncall-human-security-generation-persistence-foundation-v1") ||
		!strings.Contains(latest.DependencyEvidence, "id=20260903184951-ms-oncall-human-security-generation-persistence.sql") ||
		!strings.Contains(latest.DependencyEvidence, "sha256=442b919a8b001b9cf6ea1a118b0a5ebe7d6b674483ca867e1c264efb7e854d16") ||
		!strings.Contains(latest.DependencyEvidence, "APPEND_AFTER_IMMUTABLE_ACCEPTED_HUMAN_SECURITY_GENERATION_PERSISTENCE_FOUNDATION_V1") {
		t.Fatalf("generation retirement dependency evidence is incomplete: %s", latest.DependencyEvidence)
	}
	if latest.AdaptationEvidence != "FORWARD_RETIREMENT_OF_SUPERSEDED_SESSION_GENERATION_BINDING_AND_HUMAN_SECURITY_GENERATION_CAPABILITIES" {
		t.Fatalf("generation retirement adaptation evidence = %q", latest.AdaptationEvidence)
	}
	for _, value := range []string{
		"56e688226e2dda22376e331a16961216fc0d5501",
		"d15f45322f722598a483d2c3d87077cbfb848f0f",
		"120852c2dc74ff474d985cde9c28282a26fbbfb9",
		"985695a0cc16e787eeee2eb1d51a853a2d0d1ad2",
	} {
		if !strings.Contains(latest.SourceBinding, value) {
			t.Fatalf("generation retirement source binding is missing %q: %s", value, latest.SourceBinding)
		}
	}
}

func TestCanonicalHistoryUsesManifestOrderNotLexicalOrder(t *testing.T) {
	firstID := "20250101000000-manifest-first.sql"
	secondID := "20240101000000-manifest-second.sql"
	fixture := newHistoryFixture(t, firstID, secondID)

	history, err := loadCanonicalHistory(fixture.fsys(t))
	if err != nil {
		t.Fatal(err)
	}
	if history.entries[0].ID != firstID || history.entries[1].ID != secondID {
		t.Fatalf("canonical order = [%s, %s], want manifest order [%s, %s]", history.entries[0].ID, history.entries[1].ID, firstID, secondID)
	}
	if index, ok := history.indexByName("manifest-second"); !ok || index != 1 {
		t.Fatalf("canonical target lookup index = %d, ok = %v; want 1, true", index, ok)
	}
	if history.entries[1].PredecessorID != firstID {
		t.Fatalf("canonical predecessor = %q, want %q", history.entries[1].PredecessorID, firstID)
	}
}

func TestCanonicalHistoryRejectsCorruption(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*historyFixture)
		wantErr string
	}{
		{
			name: "duplicate canonical migration ID",
			mutate: func(f *historyFixture) {
				f.manifest.Bundles[0].Entries = append(f.manifest.Bundles[0].Entries, f.manifest.Bundles[0].Entries[0])
			},
			wantErr: "duplicate canonical migration ID",
		},
		{
			name: "duplicate migration name",
			mutate: func(f *historyFixture) {
				f.addEntry(t, "20240202000000-one.sql", []byte("-- +migrate Up\nSELECT 2;\n-- +migrate Down\n"))
			},
			wantErr: "duplicate canonical migration name",
		},
		{
			name: "missing embedded SQL",
			mutate: func(f *historyFixture) {
				delete(f.files, f.manifest.Bundles[0].Entries[0].ID)
			},
			wantErr: "missing embedded SQL",
		},
		{
			name: "checksum mismatch",
			mutate: func(f *historyFixture) {
				f.files[f.manifest.Bundles[0].Entries[0].ID] = []byte("-- +migrate Up\nSELECT 'changed';\n-- +migrate Down\n")
			},
			wantErr: "checksum mismatch",
		},
		{
			name: "unexpected embedded migration",
			mutate: func(f *historyFixture) {
				f.files["20240303000000-unexpected.sql"] = []byte("-- +migrate Up\nSELECT 3;\n-- +migrate Down\n")
			},
			wantErr: "unexpected embedded migration",
		},
		{
			name: "invalid provenance enum",
			mutate: func(f *historyFixture) {
				f.manifest.Bundles[0].Provenance = "UNKNOWN"
			},
			wantErr: "invalid provenance",
		},
		{
			name: "upstream provenance with MS OnCall source",
			mutate: func(f *historyFixture) {
				f.manifest.Bundles[0].Provenance = provenanceUpstream
			},
			wantErr: "incompatible provenance/source kind pairing",
		},
		{
			name: "MS OnCall provenance with upstream source",
			mutate: func(f *historyFixture) {
				f.manifest.Bundles[0].Source = testGoAlertReleaseSource()
			},
			wantErr: "incompatible provenance/source kind pairing",
		},
		{
			name: "unknown source kind",
			mutate: func(f *historyFixture) {
				f.manifest.Bundles[0].Source.Kind = "UNKNOWN"
			},
			wantErr: "invalid source kind",
		},
		{
			name: "invalid source metadata",
			mutate: func(f *historyFixture) {
				f.manifest.Bundles[0].Source.BaseTree = "not-a-git-tree"
			},
			wantErr: "valid base commit and tree",
		},
		{
			name: "missing adaptation evidence",
			mutate: func(f *historyFixture) {
				f.manifest.Bundles[0].AdaptationEvidence = ""
			},
			wantErr: "no adaptation evidence",
		},
		{
			name: "missing provenance Foundation designation",
			mutate: func(f *historyFixture) {
				f.manifest.ProvenanceFoundationMigrationID = ""
			},
			wantErr: "no provenance Foundation migration ID",
		},
		{
			name: "unknown provenance Foundation designation",
			mutate: func(f *historyFixture) {
				f.manifest.ProvenanceFoundationMigrationID = "20249999999999-unknown.sql"
			},
			wantErr: "provenance Foundation migration",
		},
		{
			name: "provenance Foundation is not MS OnCall",
			mutate: func(f *historyFixture) {
				f.manifest.Bundles[0].Provenance = provenanceUpstream
				f.manifest.Bundles[0].Source = historySourceSpec{
					Kind:       sourceKindGoAlertRelease,
					Repository: "https://example.invalid/goalert",
					Release:    "v0.test",
					Commit:     strings.Repeat("a", 40),
				}
			},
			wantErr: "is not MS OnCall provenance",
		},
		{
			name: "duplicate provenance identity",
			mutate: func(f *historyFixture) {
				f.addEntry(t, "20240202000000-two.sql", []byte("-- +migrate Up\nSELECT 2;\n-- +migrate Down\n"))
				f.manifest.Bundles[0].Entries[1].OriginalID = f.manifest.Bundles[0].Entries[0].OriginalID
			},
			wantErr: "duplicate migration provenance identity",
		},
		{
			name: "duplicate canonical position",
			mutate: func(f *historyFixture) {
				f.splitSecondEntryIntoBundle(t)
				f.manifest.Bundles[1].FirstPosition = 1
			},
			wantErr: "duplicate canonical migration position",
		},
		{
			name: "mismatched dependency bundle",
			mutate: func(f *historyFixture) {
				f.splitSecondEntryIntoBundle(t)
				f.manifest.Bundles[1].DependsOn.BundleID = "ms-oncall-wrong-predecessor"
			},
			wantErr: "depends on bundle",
		},
		{
			name: "mismatched dependency migration",
			mutate: func(f *historyFixture) {
				f.splitSecondEntryIntoBundle(t)
				f.manifest.Bundles[1].DependsOn.MigrationID = "20200101000000-wrong.sql"
			},
			wantErr: "does not bind exact predecessor",
		},
		{
			name: "mismatched dependency checksum",
			mutate: func(f *historyFixture) {
				f.splitSecondEntryIntoBundle(t)
				f.manifest.Bundles[1].DependsOn.SHA256 = strings.Repeat("f", 64)
			},
			wantErr: "does not bind exact predecessor",
		},
		{
			name: "missing dependency evidence",
			mutate: func(f *historyFixture) {
				f.splitSecondEntryIntoBundle(t)
				f.manifest.Bundles[1].DependsOn.Evidence = ""
			},
			wantErr: "empty dependency evidence",
		},
		{
			name: "missing bundle dependency",
			mutate: func(f *historyFixture) {
				f.splitSecondEntryIntoBundle(t)
				f.manifest.Bundles[1].DependsOn = nil
			},
			wantErr: "has no dependency evidence",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHistoryFixture(t, "20240101000000-one.sql", "20240102000000-two.sql")
			test.mutate(fixture)
			_, err := loadCanonicalHistory(fixture.fsys(t))
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("loadCanonicalHistory error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestCanonicalHistoryRejectsUnknownManifestField(t *testing.T) {
	fixture := newHistoryFixture(t, "20240101000000-one.sql")
	data, err := json.Marshal(fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data[:len(data)-1], []byte(`,"unexpected":true}`)...)
	mapFS := fixture.fsysWithManifest(data)

	_, err = loadCanonicalHistory(mapFS)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("loadCanonicalHistory error = %v, want unknown field", err)
	}
}

func TestCanonicalHistoryRejectsConflictingFoundationDesignation(t *testing.T) {
	fixture := newHistoryFixture(t, "20240101000000-one.sql")
	data, err := json.Marshal(fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	conflictingPrefix := []byte(`{"provenance_foundation_migration_id":"20249999999999-conflict.sql",`)
	data = append(conflictingPrefix, data[1:]...)

	_, err = loadCanonicalHistory(fixture.fsysWithManifest(data))
	if err == nil || !strings.Contains(err.Error(), `duplicate JSON field "provenance_foundation_migration_id"`) {
		t.Fatalf("loadCanonicalHistory error = %v, want duplicate Foundation designation", err)
	}
}

func TestCanonicalHistoryRequiresExactCanonicalJSONFields(t *testing.T) {
	const migrationID = "20240101000000-one.sql"
	fixture := newHistoryFixture(t, migrationID)
	data, err := json.Marshal(fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		mutate  func(*testing.T, []byte) []byte
		wantErr string
	}{
		{
			name: "valid exact canonical spellings",
			mutate: func(_ *testing.T, data []byte) []byte {
				return data
			},
		},
		{
			name: "uppercase Foundation key before exact key",
			mutate: func(t *testing.T, data []byte) []byte {
				return replaceManifestField(t, data,
					`"provenance_foundation_migration_id":"`+migrationID+`"`,
					`"PROVENANCE_FOUNDATION_MIGRATION_ID":"20249999999999-shadow.sql","provenance_foundation_migration_id":"`+migrationID+`"`)
			},
			wantErr: "non-canonical JSON field",
		},
		{
			name: "mixed-case Foundation key after exact key",
			mutate: func(t *testing.T, data []byte) []byte {
				return replaceManifestField(t, data,
					`"provenance_foundation_migration_id":"`+migrationID+`"`,
					`"provenance_foundation_migration_id":"`+migrationID+`","Provenance_Foundation_Migration_Id":"20249999999999-shadow.sql"`)
			},
			wantErr: "case-folded duplicate JSON field",
		},
		{
			name: "nested bundle case-fold collision",
			mutate: func(t *testing.T, data []byte) []byte {
				return replaceManifestField(t, data,
					`"id":"ms-oncall-test"`,
					`"id":"ms-oncall-test","ID":"shadow-bundle"`)
			},
			wantErr: "case-folded duplicate JSON field",
		},
		{
			name: "nested source case-fold collision",
			mutate: func(t *testing.T, data []byte) []byte {
				return replaceManifestField(t, data,
					`"kind":"MS_ONCALL_CHECKPOINT_BASE"`,
					`"kind":"MS_ONCALL_CHECKPOINT_BASE","Kind":"GOALERT_RELEASE"`)
			},
			wantErr: "case-folded duplicate JSON field",
		},
		{
			name: "migration entry case-fold collision",
			mutate: func(t *testing.T, data []byte) []byte {
				return replaceManifestField(t, data,
					`"original_id":"`+migrationID+`"`,
					`"original_id":"`+migrationID+`","Original_ID":"20249999999999-shadow.sql"`)
			},
			wantErr: "case-folded duplicate JSON field",
		},
		{
			name: "unknown nested bundle field",
			mutate: func(t *testing.T, data []byte) []byte {
				return replaceManifestField(t, data,
					`"entries":[`,
					`"unexpected":true,"entries":[`)
			},
			wantErr: "unknown field",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := test.mutate(t, append([]byte(nil), data...))
			_, err := loadCanonicalHistory(fixture.fsysWithManifest(manifest))
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("loadCanonicalHistory error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestProvenanceSourceKindCompatibilityMatrix(t *testing.T) {
	tests := []struct {
		name       string
		provenance string
		sourceKind string
		wantErr    bool
	}{
		{name: "adopted upstream GoAlert", provenance: provenanceUpstream, sourceKind: sourceKindGoAlertRelease},
		{name: "MS OnCall checkpoint", provenance: provenanceMSOnCall, sourceKind: sourceKindMSOnCallBase},
		{name: "upstream provenance with MS OnCall source", provenance: provenanceUpstream, sourceKind: sourceKindMSOnCallBase, wantErr: true},
		{name: "MS OnCall provenance with upstream source", provenance: provenanceMSOnCall, sourceKind: sourceKindGoAlertRelease, wantErr: true},
		{name: "unknown provenance", provenance: "UNKNOWN", sourceKind: sourceKindGoAlertRelease, wantErr: true},
		{name: "unknown source kind", provenance: provenanceMSOnCall, sourceKind: "UNKNOWN", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateProvenanceSourceKind(test.provenance, test.sourceKind)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateProvenanceSourceKind(%q, %q) error = %v, wantErr %v", test.provenance, test.sourceKind, err, test.wantErr)
			}
		})
	}
}

func TestCanonicalHistoryRepresentsMSOnCallUpstreamAdaptation(t *testing.T) {
	fixture := newUpstreamAdaptationFixture(t)
	history, err := loadCanonicalHistory(fixture.fsys(t))
	if err != nil {
		t.Fatal(err)
	}

	adapted := history.entries[1]
	if adapted.Provenance != provenanceMSOnCall {
		t.Fatalf("adaptation provenance = %q, want %q", adapted.Provenance, provenanceMSOnCall)
	}
	source, err := parseCanonicalSourceBinding(adapted.SourceBinding)
	if err != nil {
		t.Fatal(err)
	}
	if source.Kind != sourceKindMSOnCallBase {
		t.Fatalf("adaptation source kind = %q, want %q", source.Kind, sourceKindMSOnCallBase)
	}
	if adapted.AdaptationEvidence != "ADAPTS_EXACT_UPSTREAM_PREDECESSOR_FOR_TEST" {
		t.Fatalf("adaptation evidence = %q", adapted.AdaptationEvidence)
	}
	if !strings.Contains(adapted.DependencyEvidence, history.entries[0].ID) || !strings.Contains(adapted.DependencyEvidence, history.entries[0].SHA256) {
		t.Fatalf("adaptation dependency does not bind upstream predecessor: %s", adapted.DependencyEvidence)
	}
}

func TestCanonicalHistoryRejectsIncompleteOrContradictoryAdaptation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*historyFixture)
		wantErr string
	}{
		{
			name: "missing adaptation evidence",
			mutate: func(f *historyFixture) {
				f.manifest.Bundles[1].AdaptationEvidence = ""
			},
			wantErr: "no adaptation evidence",
		},
		{
			name: "missing upstream dependency",
			mutate: func(f *historyFixture) {
				f.manifest.Bundles[1].DependsOn = nil
			},
			wantErr: "has no dependency evidence",
		},
		{
			name: "adaptation mislabeled as upstream source",
			mutate: func(f *historyFixture) {
				f.manifest.Bundles[1].Source = testGoAlertReleaseSource()
			},
			wantErr: "incompatible provenance/source kind pairing",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newUpstreamAdaptationFixture(t)
			test.mutate(fixture)
			_, err := loadCanonicalHistory(fixture.fsys(t))
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("loadCanonicalHistory error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

type historyFixture struct {
	manifest historyManifest
	files    map[string][]byte
}

func newHistoryFixture(t *testing.T, ids ...string) *historyFixture {
	t.Helper()
	fixture := &historyFixture{
		manifest: historyManifest{
			FormatVersion: historyFormatVersion,
			Bundles: []historyBundleSpec{{
				ID:            "ms-oncall-test",
				FirstPosition: 1,
				Provenance:    provenanceMSOnCall,
				Source: historySourceSpec{
					Kind:                    sourceKindMSOnCallBase,
					Repository:              "https://example.invalid/ms-oncall",
					Checkpoint:              "test-checkpoint",
					BaseCommit:              strings.Repeat("1", 40),
					BaseTree:                strings.Repeat("2", 40),
					AuthorizationRepository: "https://example.invalid/ms-oncall-project",
					AuthorizationCommit:     strings.Repeat("3", 40),
					AuthorizationTree:       strings.Repeat("4", 40),
				},
				AdaptationEvidence: "NOT_APPLICABLE_TEST",
			}},
			ProvenanceFoundationMigrationID: ids[0],
		},
		files: make(map[string][]byte),
	}
	for index, id := range ids {
		sqlData := []byte(fmt.Sprintf("-- +migrate Up\nSELECT %d;\n-- +migrate Down\n", index+1))
		fixture.addEntry(t, id, sqlData)
	}
	return fixture
}

func (f *historyFixture) addEntry(t *testing.T, id string, data []byte) {
	t.Helper()
	checksum := fmt.Sprintf("%x", sha256.Sum256(data))
	f.files[id] = data
	f.manifest.Bundles[0].Entries = append(f.manifest.Bundles[0].Entries, historyEntrySpec{
		ID:         id,
		OriginalID: id,
		SHA256:     checksum,
	})
}

func (f *historyFixture) splitSecondEntryIntoBundle(t *testing.T) {
	t.Helper()
	if len(f.manifest.Bundles) != 1 || len(f.manifest.Bundles[0].Entries) < 2 {
		t.Fatal("fixture needs at least two entries")
	}
	firstBundle := &f.manifest.Bundles[0]
	secondEntry := firstBundle.Entries[len(firstBundle.Entries)-1]
	firstBundle.Entries = firstBundle.Entries[:len(firstBundle.Entries)-1]
	predecessor := firstBundle.Entries[len(firstBundle.Entries)-1]
	f.manifest.Bundles = append(f.manifest.Bundles, historyBundleSpec{
		ID:            "ms-oncall-test-followup",
		FirstPosition: int64(len(firstBundle.Entries) + 1),
		Provenance:    provenanceMSOnCall,
		Source: historySourceSpec{
			Kind:                    sourceKindMSOnCallBase,
			Repository:              "https://example.invalid/ms-oncall",
			Checkpoint:              "test-followup",
			BaseCommit:              strings.Repeat("3", 40),
			BaseTree:                strings.Repeat("4", 40),
			AuthorizationRepository: "https://example.invalid/ms-oncall-project",
			AuthorizationCommit:     strings.Repeat("5", 40),
			AuthorizationTree:       strings.Repeat("6", 40),
		},
		DependsOn: &historyDependencySpec{
			BundleID:    firstBundle.ID,
			MigrationID: predecessor.ID,
			SHA256:      predecessor.SHA256,
			Evidence:    "TEST_APPEND",
		},
		AdaptationEvidence: "NOT_APPLICABLE_TEST",
		Entries:            []historyEntrySpec{secondEntry},
	})
}

func (f *historyFixture) fsys(t *testing.T) fs.FS {
	t.Helper()
	data, err := json.Marshal(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	return f.fsysWithManifest(data)
}

func (f *historyFixture) fsysWithManifest(manifest []byte) fs.FS {
	mapFS := fstest.MapFS{
		"history.json": &fstest.MapFile{Data: manifest},
	}
	for id, data := range f.files {
		mapFS["migrations/"+id] = &fstest.MapFile{Data: data}
	}
	return mapFS
}

func replaceManifestField(t *testing.T, data []byte, old, replacement string) []byte {
	t.Helper()
	result := strings.Replace(string(data), old, replacement, 1)
	if result == string(data) {
		t.Fatalf("manifest fixture does not contain %q", old)
	}
	return []byte(result)
}

func testGoAlertReleaseSource() historySourceSpec {
	return historySourceSpec{
		Kind:       sourceKindGoAlertRelease,
		Repository: "https://example.invalid/goalert",
		Release:    "v0.test",
		Commit:     strings.Repeat("a", 40),
	}
}

func newUpstreamAdaptationFixture(t *testing.T) *historyFixture {
	t.Helper()
	fixture := newHistoryFixture(t,
		"20240101000000-upstream.sql",
		"20240102000000-ms-oncall-adaptation.sql",
	)
	fixture.splitSecondEntryIntoBundle(t)
	fixture.manifest.Bundles[0].Provenance = provenanceUpstream
	fixture.manifest.Bundles[0].Source = testGoAlertReleaseSource()
	fixture.manifest.Bundles[0].AdaptationEvidence = "NONE_BYTE_IDENTICAL_TO_ADOPTED_UPSTREAM_RELEASE_TEST"
	fixture.manifest.Bundles[1].AdaptationEvidence = "ADAPTS_EXACT_UPSTREAM_PREDECESSOR_FOR_TEST"
	fixture.manifest.ProvenanceFoundationMigrationID = fixture.manifest.Bundles[1].Entries[0].ID
	return fixture
}
