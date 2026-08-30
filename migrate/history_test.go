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
	if got, want := len(history.entries), 275; got != want {
		t.Fatalf("canonical entry count = %d, want %d", got, want)
	}
	if got, want := history.provenanceStoreIndex, len(history.entries)-1; got != want {
		t.Fatalf("provenance store index = %d, want %d", got, want)
	}
	for _, entry := range history.entries[:history.provenanceStoreIndex] {
		if entry.Provenance != provenanceUpstream {
			t.Fatalf("historical migration %q provenance = %q, want %q", entry.ID, entry.Provenance, provenanceUpstream)
		}
		if !strings.Contains(entry.SourceBinding, "0918387e38650aaddd6a923d445ee992f64d6ab6") {
			t.Fatalf("historical migration %q is not bound to adopted GoAlert v0.34.1 commit", entry.ID)
		}
	}
	latest := history.latest()
	if latest.ID != "20260830195814-ms-oncall-migration-provenance.sql" {
		t.Fatalf("latest migration = %q", latest.ID)
	}
	if latest.Provenance != provenanceMSOnCall {
		t.Fatalf("latest migration provenance = %q, want %q", latest.Provenance, provenanceMSOnCall)
	}
	if !strings.Contains(latest.SourceBinding, "e4f097077c15f6e6ae0fa2e5fc3d61938e295970") ||
		!strings.Contains(latest.SourceBinding, "7cc13bed88ba5483ab1f60e4a9628ff8261569c6") ||
		!strings.Contains(latest.SourceBinding, "0a9ba1131988608ffdc7a4faa9cdf72ea6ccc74b") ||
		!strings.Contains(latest.SourceBinding, "e3c20a00455d0c6bd247e8c547bd658eaf5b6c41") {
		t.Fatalf("MS OnCall foundation source binding does not contain the exact parent commit and tree: %s", latest.SourceBinding)
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
			name: "invalid bundle dependency",
			mutate: func(f *historyFixture) {
				f.splitSecondEntryIntoBundle(t)
				f.manifest.Bundles[1].DependsOn.MigrationID = "20200101000000-wrong.sql"
			},
			wantErr: "does not bind exact predecessor",
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
			ProvenanceStoreMigrationID: ids[0],
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
