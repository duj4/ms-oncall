package migrate

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicMigrationMetadataUsesCanonicalHistory(t *testing.T) {
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := LatestID(), history.latest().ID; got != want {
		t.Fatalf("LatestID = %q, want %q", got, want)
	}
	names := Names()
	if len(names) != len(history.entries) {
		t.Fatalf("Names length = %d, want %d", len(names), len(history.entries))
	}
	for index, entry := range history.entries {
		if names[index] != entry.Name {
			t.Fatalf("Names[%d] = %q, want %q", index, names[index], entry.Name)
		}
		gotIndex, ok := history.indexByName(entry.Name)
		if !ok || gotIndex != index || history.entries[gotIndex].ID != entry.ID {
			t.Fatalf("canonical name lookup %q = (%d, %v), want (%d, true)", entry.Name, gotIndex, ok, index)
		}
	}
}

func TestCanonicalMigrationPlansIgnoreLexicalIDOrder(t *testing.T) {
	migrations := []migration{
		{ID: "20250101000000-manifest-first.sql"},
		{ID: "20230101000000-manifest-second.sql"},
		{ID: "20240101000000-manifest-third.sql"},
	}
	up := planUpMigrations(migrations, 1, 2)
	if len(up) != 2 || up[0].ID != migrations[1].ID || up[1].ID != migrations[2].ID {
		t.Fatalf("Up plan = %#v, want canonical suffix [%s, %s]", up, migrations[1].ID, migrations[2].ID)
	}
	down := planDownMigrations(migrations, 3, 0)
	if len(down) != 2 || down[0].ID != migrations[2].ID || down[1].ID != migrations[1].ID {
		t.Fatalf("Down plan = %#v, want reverse canonical suffix [%s, %s]", down, migrations[2].ID, migrations[1].ID)
	}
}

func TestParseMigrationsUsesCanonicalSequence(t *testing.T) {
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := parseMigrations(history)
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) != len(history.entries) {
		t.Fatalf("parsed migration count = %d, want %d", len(migrations), len(history.entries))
	}
	for index, migration := range migrations {
		if migration.ID != history.entries[index].ID || migration.Name != history.entries[index].Name {
			t.Fatalf("parsed migration %d = (%q, %q), want (%q, %q)", index, migration.ID, migration.Name, history.entries[index].ID, history.entries[index].Name)
		}
	}
}

func TestProvenanceFoundationMigrationUsesTransaction(t *testing.T) {
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := parseMigrations(history)
	if err != nil {
		t.Fatal(err)
	}
	foundation := migrations[history.provenanceFoundationIndex]
	if foundation.Up.disableTx || foundation.Down.disableTx {
		t.Fatalf("provenance Foundation migration %q must use transactions for Up and Down", foundation.ID)
	}
}

func TestMSOnCallPersistenceMigrationsUseTransactions(t *testing.T) {
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := parseMigrations(history)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations[len(migrations)-2:] {
		if migration.Up.disableTx || migration.Down.disableTx {
			t.Fatalf("MS OnCall persistence migration %q must use transactions for Up and Down", migration.ID)
		}
		if len(migration.Up.statements) == 0 || len(migration.Down.statements) == 0 {
			t.Fatalf("MS OnCall persistence migration %q has an empty direction", migration.ID)
		}
	}
	latest := migrations[len(migrations)-1]
	if latest.ID != "20260901220323-ms-oncall-user-organization-assignment-persistence.sql" {
		t.Fatalf("latest migration = %q", latest.ID)
	}
}

func TestDumpMigrationsIncludesValidatedCanonicalHistory(t *testing.T) {
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := DumpMigrations(dest); err != nil {
		t.Fatal(err)
	}

	dumpedManifest, err := os.ReadFile(filepath.Join(dest, "migration-history.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dumpedManifest, history.manifest) {
		t.Fatal("dumped canonical history differs from embedded accepted manifest")
	}
	files, err := os.ReadDir(filepath.Join(dest, "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(history.entries) {
		t.Fatalf("dumped migration count = %d, want %d", len(files), len(history.entries))
	}
	for _, entry := range history.entries {
		dumped, err := os.ReadFile(filepath.Join(dest, "migrations", entry.ID))
		if err != nil {
			t.Fatal(err)
		}
		embedded, err := readMigration(entry.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dumped, embedded) {
			t.Fatalf("dumped migration %q differs from embedded SQL", entry.ID)
		}
	}
}
