package migrate

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

func TestMSOnCallTailMigrationsUseTransactions(t *testing.T) {
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := parseMigrations(history)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations[len(migrations)-5:] {
		if migration.Up.disableTx || migration.Down.disableTx {
			t.Fatalf("MS OnCall persistence migration %q must use transactions for Up and Down", migration.ID)
		}
		if len(migration.Up.statements) == 0 || len(migration.Down.statements) == 0 {
			t.Fatalf("MS OnCall persistence migration %q has an empty direction", migration.ID)
		}
	}
	latest := migrations[len(migrations)-1]
	if latest.ID != "20260907222039-ms-oncall-active-foundation-reconciliation-v1.sql" {
		t.Fatalf("latest migration = %q", latest.ID)
	}
}

func TestGenerationRetirementDownRestoresExactPosition278Definition(t *testing.T) {
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := parseMigrations(history)
	if err != nil {
		t.Fatal(err)
	}
	position278 := migrations[len(migrations)-3]
	position279 := migrations[len(migrations)-2]
	if position278.ID != "20260903184951-ms-oncall-human-security-generation-persistence.sql" ||
		position279.ID != "20260905230921-ms-oncall-session-generation-binding-human-security-generation-retirement-cleanup-v1.sql" {
		t.Fatalf("unexpected retirement boundary: position278=%q position279=%q", position278.ID, position279.ID)
	}
	if !slices.Equal(position279.Down.statements, position278.Up.statements) {
		t.Fatal("position-279 Down does not exactly reproduce the parsed position-278 Up definition")
	}
}

func TestActiveFoundationReconciliationMigrationIsNarrowAndGuardsLossyDown(t *testing.T) {
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := parseMigrations(history)
	if err != nil {
		t.Fatal(err)
	}
	position280 := migrations[len(migrations)-1]
	if position280.ID != "20260907222039-ms-oncall-active-foundation-reconciliation-v1.sql" {
		t.Fatalf("position-280 migration = %q", position280.ID)
	}
	if position280.Up.disableTx || position280.Down.disableTx || len(position280.Up.statements) == 0 || len(position280.Down.statements) == 0 {
		t.Fatal("position-280 migration must have transactional, non-empty Up and Down directions")
	}
	up := strings.Join(position280.Up.statements, "\n")
	down := strings.Join(position280.Down.statements, "\n")
	for _, removed := range []string{"lifecycle", "assignment_generation", "evidence_digest", "pending_transfer_id", "ms_oncall_user_organization_assignment_state"} {
		if !strings.Contains(up, removed) || !strings.Contains(down, removed) {
			t.Fatalf("position-280 directions do not both account for %q", removed)
		}
	}
	if !strings.HasPrefix(strings.TrimSpace(position280.Down.statements[0]), "LOCK TABLE public.organizations, public.normal_organizations, public.user_organization_assignments") {
		t.Fatalf("position-280 Down does not acquire its write-excluding table locks first: %q", position280.Down.statements[0])
	}
	guard := position280.Down.statements[1]
	if !strings.Contains(guard, "position-280 downgrade refused: current Organization or assignment rows require discarded authority state") ||
		!strings.Contains(guard, "FROM public.user_organization_assignments") ||
		!strings.Contains(guard, "FROM public.normal_organizations") ||
		!strings.Contains(guard, "FROM public.organizations") {
		t.Fatalf("position-280 Down lacks the bounded pre-mutation refusal guard: %q", guard)
	}
	if strings.Contains(position280.Down.statements[0], "DROP ") || strings.Contains(guard, "DROP ") ||
		strings.Contains(position280.Down.statements[0], "ALTER ") || strings.Contains(guard, "ALTER ") {
		t.Fatal("position-280 Down mutates schema before its lossy-downgrade guard")
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
