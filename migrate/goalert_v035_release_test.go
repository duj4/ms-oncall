package migrate

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestGoAlertV035ReleaseCanonicalBundle(t *testing.T) {
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ id, checksum string }{
		{"20251003121427-alert-status-direct-event.sql", "648f9de6f3ac1d95a075bc70deca41e36f6740a086fa2ff671476230388dae02"},
		{"20251003123243-rotation-direct-event.sql", "d6a1d203e4cb4642a2e60f84c7cd297c49d9fb95b812ad063a4e7516ccd37d3b"},
		{"20251003130424-signals-direct-event.sql", "e9ccc1186977d48524d53af6ea519b62d2b35d1f684e17043811dd72017f9b4d"},
		{"20251021155802-fix-queue-name.sql", "43337a03e5550e5021ef09c56893c7c670e0513bb1dd2ec13a8ded828248b1f6"},
		{"20260624104709-schedule-rotation-ep-labels.sql", "07546f9c760812aca7914b6ff2c4a84ad8625c66e37f64b9e72d817d1be6c9c6"},
		{"20260814161833-ep-step-multi-ack.sql", "769e82c803ea88a1ac9ed1cbe1b384d71d8849bb029cb62e4c05bc3675cb3167"},
		{"20260911125511-cm-private.sql", "23eafcf4a412ca8dc7484706fd7ca24b9de8dcf1b5b5e8e177e7d7d5b1fa027e"},
	}
	if len(history.entries) < 281+len(want) {
		t.Fatalf("canonical entry count = %d, want at least 288", len(history.entries))
	}
	predecessor := history.entries[281-1]
	for i, expected := range want {
		entry := history.entries[281+i]
		if entry.Position != int64(282+i) || entry.ID != expected.id || entry.OriginalID != expected.id || entry.SHA256 != expected.checksum {
			t.Fatalf("release entry %d identity/checksum = %#v", i, entry)
		}
		if entry.Provenance != provenanceUpstream || entry.BundleID != "goalert-v0.35.0" || entry.PredecessorID != predecessor.ID {
			t.Fatalf("release entry %d provenance/predecessor = %#v", i, entry)
		}
		source, err := parseCanonicalSourceBinding(entry.SourceBinding)
		if err != nil {
			t.Fatal(err)
		}
		if source.Kind != sourceKindGoAlertRelease || source.Repository != "https://github.com/target/goalert" || source.Release != "v0.35.0" || source.Commit != "db9829187a1c1f96a7c57112b74dba54442d7c6b" {
			t.Fatalf("release entry %d source = %#v", i, source)
		}
		if entry.AdaptationEvidence != "NONE_BYTE_IDENTICAL_TO_ADOPTED_UPSTREAM_RELEASE" {
			t.Fatalf("release entry %d adaptation evidence = %q", i, entry.AdaptationEvidence)
		}
		bindings := []string{"id=" + predecessor.ID, "sha256=" + predecessor.SHA256}
		if i == 0 {
			bindings = append(bindings, "bundle=ms-oncall-resource-root-organization-ownership-persistence-v1")
		}
		for _, binding := range bindings {
			if !strings.Contains(entry.DependencyEvidence, binding) {
				t.Fatalf("release entry %d dependency is missing %q", i, binding)
			}
		}
		predecessor = entry
	}
}

func TestPostgresGoAlertV035ReleaseUpgrade(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	testURL := newPostgresTestDatabase(t, baseURL)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if count, err := Up(ctx, testURL, history.entries[281-1].Name); err != nil || count != 281 {
		t.Fatalf("canonical starting state = (%d, %v), want 281", count, err)
	}
	if count, err := Up(ctx, testURL, history.entries[288-1].Name); err != nil || count != 7 {
		t.Fatalf("release upgrade = (%d, %v), want seven applied migrations", count, err)
	}
	releaseHistory := *history
	releaseHistory.entries = history.entries[:288]
	assertDeterministicProvenanceState(t, ctx, testURL, &releaseHistory)
	for name, verify := range map[string]func(context.Context, string) error{
		"VerifyAll": VerifyAll, "VerifyIsLatest": VerifyIsLatest,
	} {
		err := verify(ctx, testURL)
		if len(history.entries) == 288 {
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), history.latest().Name) {
			t.Fatalf("%s = %v, want pending forward migration", name, err)
		}
	}
	if count, err := Up(ctx, testURL, history.entries[288-1].Name); err != nil || count != 0 {
		t.Fatalf("repeated release upgrade = (%d, %v), want no-op", count, err)
	}
}
