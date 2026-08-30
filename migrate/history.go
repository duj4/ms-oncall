package migrate

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
)

const (
	historyFormatVersion = 1

	provenanceUpstream = "UPSTREAM_GOALERT"
	provenanceMSOnCall = "MS_ONCALL"

	sourceKindGoAlertRelease = "GOALERT_RELEASE"
	sourceKindMSOnCallBase   = "MS_ONCALL_CHECKPOINT_BASE"
)

//go:embed migrations history.json
var migrationFS embed.FS

type historyManifest struct {
	FormatVersion              int                 `json:"format_version"`
	ProvenanceStoreMigrationID string              `json:"provenance_store_migration_id"`
	Bundles                    []historyBundleSpec `json:"bundles"`
}

type historyBundleSpec struct {
	ID                 string                 `json:"id"`
	FirstPosition      int64                  `json:"first_position"`
	Provenance         string                 `json:"provenance"`
	Source             historySourceSpec      `json:"source"`
	DependsOn          *historyDependencySpec `json:"depends_on,omitempty"`
	AdaptationEvidence string                 `json:"adaptation_evidence"`
	Entries            []historyEntrySpec     `json:"entries"`
}

type historySourceSpec struct {
	Kind                    string `json:"kind"`
	Repository              string `json:"repository"`
	Release                 string `json:"release,omitempty"`
	Commit                  string `json:"commit,omitempty"`
	Checkpoint              string `json:"checkpoint,omitempty"`
	BaseCommit              string `json:"base_commit,omitempty"`
	BaseTree                string `json:"base_tree,omitempty"`
	AuthorizationRepository string `json:"authorization_repository,omitempty"`
	AuthorizationCommit     string `json:"authorization_commit,omitempty"`
	AuthorizationTree       string `json:"authorization_tree,omitempty"`
}

type historyDependencySpec struct {
	BundleID    string `json:"bundle_id"`
	MigrationID string `json:"migration_id"`
	SHA256      string `json:"sha256"`
	Evidence    string `json:"evidence"`
}

type historyEntrySpec struct {
	ID         string `json:"id"`
	OriginalID string `json:"original_id"`
	SHA256     string `json:"sha256"`
}

type canonicalMigration struct {
	Position           int64
	ID                 string
	Name               string
	Provenance         string
	OriginalID         string
	SHA256             string
	SourceBinding      string
	BundleID           string
	PredecessorID      string
	DependencyEvidence string
	AdaptationEvidence string
}

type canonicalHistory struct {
	entries              []canonicalMigration
	byID                 map[string]int
	byName               map[string]int
	provenanceStoreIndex int
	manifest             []byte
}

func (h *canonicalHistory) indexByName(name string) (int, bool) {
	i, ok := h.byName[name]
	return i, ok
}

func (h *canonicalHistory) indexByID(id string) (int, bool) {
	i, ok := h.byID[id]
	return i, ok
}

func (h *canonicalHistory) latest() canonicalMigration {
	return h.entries[len(h.entries)-1]
}

var (
	embeddedHistoryOnce sync.Once
	embeddedHistory     *canonicalHistory
	embeddedHistoryErr  error
)

func loadEmbeddedHistory() (*canonicalHistory, error) {
	embeddedHistoryOnce.Do(func() {
		embeddedHistory, embeddedHistoryErr = loadCanonicalHistory(migrationFS)
	})
	return embeddedHistory, embeddedHistoryErr
}

func mustEmbeddedHistory() *canonicalHistory {
	history, err := loadEmbeddedHistory()
	if err != nil {
		panic(fmt.Sprintf("invalid canonical migration history: %v", err))
	}
	return history
}

func loadCanonicalHistory(fsys fs.FS) (*canonicalHistory, error) {
	manifestData, err := fs.ReadFile(fsys, "history.json")
	if err != nil {
		return nil, fmt.Errorf("read canonical migration history: %w", err)
	}

	var manifest historyManifest
	decoder := json.NewDecoder(bytes.NewReader(manifestData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode canonical migration history: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode canonical migration history: %w", err)
	}
	if manifest.FormatVersion != historyFormatVersion {
		return nil, fmt.Errorf("unsupported canonical migration history format %d", manifest.FormatVersion)
	}
	if len(manifest.Bundles) == 0 {
		return nil, fmt.Errorf("canonical migration history has no bundles")
	}
	if manifest.ProvenanceStoreMigrationID == "" {
		return nil, fmt.Errorf("canonical migration history has no provenance-store migration ID")
	}

	history := &canonicalHistory{
		byID:                 make(map[string]int),
		byName:               make(map[string]int),
		provenanceStoreIndex: -1,
		manifest:             append([]byte(nil), manifestData...),
	}
	bundleIDs := make(map[string]struct{})
	positions := make(map[int64]string)
	provenanceIDs := make(map[string]string)
	expectedPosition := int64(1)

	for bundleIndex, bundle := range manifest.Bundles {
		if bundle.ID == "" {
			return nil, fmt.Errorf("canonical migration bundle %d has no ID", bundleIndex)
		}
		if _, ok := bundleIDs[bundle.ID]; ok {
			return nil, fmt.Errorf("duplicate canonical migration bundle ID %q", bundle.ID)
		}
		bundleIDs[bundle.ID] = struct{}{}
		if len(bundle.Entries) == 0 {
			return nil, fmt.Errorf("canonical migration bundle %q has no entries", bundle.ID)
		}
		if bundle.FirstPosition < expectedPosition {
			return nil, fmt.Errorf("duplicate canonical migration position %d in bundle %q", bundle.FirstPosition, bundle.ID)
		}
		if bundle.FirstPosition > expectedPosition {
			return nil, fmt.Errorf("canonical migration position gap: bundle %q starts at %d, expected %d", bundle.ID, bundle.FirstPosition, expectedPosition)
		}
		if bundle.Provenance != provenanceUpstream && bundle.Provenance != provenanceMSOnCall {
			return nil, fmt.Errorf("invalid provenance %q for bundle %q", bundle.Provenance, bundle.ID)
		}
		if bundle.AdaptationEvidence == "" {
			return nil, fmt.Errorf("bundle %q has no adaptation evidence", bundle.ID)
		}

		sourceBinding, err := validateSource(bundle.Source)
		if err != nil {
			return nil, fmt.Errorf("bundle %q source: %w", bundle.ID, err)
		}
		if err := validateBundleDependency(bundleIndex, bundle, manifest.Bundles, history.entries); err != nil {
			return nil, err
		}

		for entryIndex, spec := range bundle.Entries {
			position := bundle.FirstPosition + int64(entryIndex)
			if previousID, ok := positions[position]; ok {
				return nil, fmt.Errorf("duplicate canonical migration position %d for %q and %q", position, previousID, spec.ID)
			}
			positions[position] = spec.ID

			name, err := migrationNameFromID(spec.ID)
			if err != nil {
				return nil, fmt.Errorf("bundle %q migration %q: %w", bundle.ID, spec.ID, err)
			}
			if _, ok := history.byID[spec.ID]; ok {
				return nil, fmt.Errorf("duplicate canonical migration ID %q", spec.ID)
			}
			if previous, ok := history.byName[name]; ok {
				return nil, fmt.Errorf("duplicate canonical migration name %q for %q and %q", name, history.entries[previous].ID, spec.ID)
			}
			if spec.OriginalID == "" {
				return nil, fmt.Errorf("canonical migration %q has no original migration identity", spec.ID)
			}
			if err := validateSHA256(spec.SHA256); err != nil {
				return nil, fmt.Errorf("canonical migration %q checksum: %w", spec.ID, err)
			}

			provenanceID := bundle.Provenance + "\x00" + sourceBinding + "\x00" + spec.OriginalID
			if previousID, ok := provenanceIDs[provenanceID]; ok {
				return nil, fmt.Errorf("duplicate migration provenance identity for %q and %q", previousID, spec.ID)
			}
			provenanceIDs[provenanceID] = spec.ID

			data, err := fs.ReadFile(fsys, "migrations/"+spec.ID)
			if err != nil {
				return nil, fmt.Errorf("canonical migration %q missing embedded SQL: %w", spec.ID, err)
			}
			actual := fmt.Sprintf("%x", sha256.Sum256(data))
			if actual != spec.SHA256 {
				return nil, fmt.Errorf("canonical migration %q checksum mismatch: got %s, expected %s", spec.ID, actual, spec.SHA256)
			}

			entry := canonicalMigration{
				Position:           position,
				ID:                 spec.ID,
				Name:               name,
				Provenance:         bundle.Provenance,
				OriginalID:         spec.OriginalID,
				SHA256:             spec.SHA256,
				SourceBinding:      sourceBinding,
				BundleID:           bundle.ID,
				AdaptationEvidence: bundle.AdaptationEvidence,
			}
			if len(history.entries) == 0 {
				entry.DependencyEvidence = "CANONICAL_HISTORY_ROOT"
			} else {
				previous := history.entries[len(history.entries)-1]
				entry.PredecessorID = previous.ID
				entry.DependencyEvidence = fmt.Sprintf("CANONICAL_PREDECESSOR|id=%s|sha256=%s", previous.ID, previous.SHA256)
				if entryIndex == 0 {
					dependency := bundle.DependsOn
					entry.DependencyEvidence = fmt.Sprintf("BUNDLE_DEPENDENCY|bundle=%s|id=%s|sha256=%s|evidence=%s", dependency.BundleID, dependency.MigrationID, dependency.SHA256, dependency.Evidence)
				}
			}

			history.byID[entry.ID] = len(history.entries)
			history.byName[entry.Name] = len(history.entries)
			history.entries = append(history.entries, entry)
			expectedPosition++
		}
	}

	storeIndex, ok := history.byID[manifest.ProvenanceStoreMigrationID]
	if !ok {
		return nil, fmt.Errorf("provenance-store migration %q is not in canonical history", manifest.ProvenanceStoreMigrationID)
	}
	if history.entries[storeIndex].Provenance != provenanceMSOnCall {
		return nil, fmt.Errorf("provenance-store migration %q is not MS OnCall provenance", manifest.ProvenanceStoreMigrationID)
	}
	history.provenanceStoreIndex = storeIndex

	dirEntries, err := fs.ReadDir(fsys, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migration directory: %w", err)
	}
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			return nil, fmt.Errorf("unexpected embedded migration directory %q outside canonical history", dirEntry.Name())
		}
		if _, ok := history.byID[dirEntry.Name()]; !ok {
			return nil, fmt.Errorf("unexpected embedded migration %q outside canonical history", dirEntry.Name())
		}
	}
	if len(dirEntries) != len(history.entries) {
		return nil, fmt.Errorf("canonical migration count %d does not match embedded migration count %d", len(history.entries), len(dirEntries))
	}

	return history, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("multiple JSON values")
	}
	return err
}

func validateSource(source historySourceSpec) (string, error) {
	if source.Repository == "" {
		return "", fmt.Errorf("repository is required")
	}
	switch source.Kind {
	case sourceKindGoAlertRelease:
		if source.Release == "" {
			return "", fmt.Errorf("release is required for %s", source.Kind)
		}
		if !validGitObjectID(source.Commit) {
			return "", fmt.Errorf("valid source commit is required for %s", source.Kind)
		}
		if source.Checkpoint != "" || source.BaseCommit != "" || source.BaseTree != "" ||
			source.AuthorizationRepository != "" || source.AuthorizationCommit != "" || source.AuthorizationTree != "" {
			return "", fmt.Errorf("MS OnCall checkpoint fields are invalid for %s", source.Kind)
		}
	case sourceKindMSOnCallBase:
		if source.Checkpoint == "" {
			return "", fmt.Errorf("checkpoint is required for %s", source.Kind)
		}
		if !validGitObjectID(source.BaseCommit) || !validGitObjectID(source.BaseTree) {
			return "", fmt.Errorf("valid base commit and tree are required for %s", source.Kind)
		}
		if source.AuthorizationRepository == "" || !validGitObjectID(source.AuthorizationCommit) || !validGitObjectID(source.AuthorizationTree) {
			return "", fmt.Errorf("valid authorization repository, commit, and tree are required for %s", source.Kind)
		}
		if source.Release != "" || source.Commit != "" {
			return "", fmt.Errorf("upstream release fields are invalid for %s", source.Kind)
		}
	default:
		return "", fmt.Errorf("invalid source kind %q", source.Kind)
	}

	data, err := json.Marshal(source)
	if err != nil {
		return "", fmt.Errorf("encode source binding: %w", err)
	}
	return string(data), nil
}

func validateBundleDependency(bundleIndex int, bundle historyBundleSpec, bundles []historyBundleSpec, entries []canonicalMigration) error {
	if bundleIndex == 0 {
		if bundle.DependsOn != nil {
			return fmt.Errorf("root canonical migration bundle %q cannot declare a dependency", bundle.ID)
		}
		return nil
	}
	if bundle.DependsOn == nil {
		return fmt.Errorf("canonical migration bundle %q has no dependency evidence", bundle.ID)
	}
	dependency := bundle.DependsOn
	previousBundle := bundles[bundleIndex-1]
	previousEntry := entries[len(entries)-1]
	if dependency.BundleID != previousBundle.ID {
		return fmt.Errorf("canonical migration bundle %q depends on bundle %q, expected %q", bundle.ID, dependency.BundleID, previousBundle.ID)
	}
	if dependency.MigrationID != previousEntry.ID || dependency.SHA256 != previousEntry.SHA256 {
		return fmt.Errorf("canonical migration bundle %q dependency does not bind exact predecessor %q", bundle.ID, previousEntry.ID)
	}
	if dependency.Evidence == "" {
		return fmt.Errorf("canonical migration bundle %q has empty dependency evidence", bundle.ID)
	}
	return nil
}

func migrationNameFromID(id string) (string, error) {
	if strings.Contains(id, "/") || len(id) <= 19 || id[14] != '-' || !strings.HasSuffix(id, ".sql") {
		return "", fmt.Errorf("invalid migration ID format")
	}
	for _, char := range id[:14] {
		if char < '0' || char > '9' {
			return "", fmt.Errorf("invalid migration timestamp prefix")
		}
	}
	name := strings.TrimSuffix(id[15:], ".sql")
	if name == "" {
		return "", fmt.Errorf("migration name is empty")
	}
	return name, nil
}

func validateSHA256(value string) error {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return fmt.Errorf("must be 64 lowercase hexadecimal characters")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("must be valid hexadecimal: %w", err)
	}
	return nil
}

func validGitObjectID(value string) bool {
	if len(value) != 40 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
