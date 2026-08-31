package migrate

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5"
)

const (
	recordOriginPreLedgerBootstrap = "PRE_LEDGER_BOOTSTRAP"
	recordOriginCanonical          = "CANONICAL_EXECUTION"
)

type appliedMigrationRecord struct {
	ID        string
	AppliedAt sql.NullTime
}

type appliedProvenanceRecord struct {
	CanonicalPosition   int64
	MigrationID         string
	MigrationName       string
	ProvenanceClass     string
	OriginalMigrationID string
	ContentSHA256       string
	SourceBinding       string
	BundleID            string
	PredecessorID       sql.NullString
	DependencyEvidence  string
	AdaptationEvidence  string
	RecordOrigin        string
	AppliedAt           sql.NullTime
}

type resolvedCanonicalMigration struct {
	canonicalMigration
	Applied bool
}

func resolveCanonicalHistory(history *canonicalHistory, appliedCount int) []resolvedCanonicalMigration {
	resolved := make([]resolvedCanonicalMigration, len(history.entries))
	for i, entry := range history.entries {
		resolved[i] = resolvedCanonicalMigration{
			canonicalMigration: entry,
			Applied:            i < appliedCount,
		}
	}
	return resolved
}

func loadAppliedHistory(ctx context.Context, conn *pgx.Conn, history *canonicalHistory) ([]resolvedCanonicalMigration, error) {
	applied, err := readAppliedMigrationRecords(ctx, conn)
	if err != nil {
		return nil, err
	}
	hasProvenance, err := provenanceTableExists(ctx, conn)
	if err != nil {
		return nil, err
	}
	var provenance []appliedProvenanceRecord
	if hasProvenance {
		provenance, err = readAppliedProvenanceRecords(ctx, conn)
		if err != nil {
			return nil, err
		}
	}

	appliedCount, err := validateAppliedHistory(history, applied, hasProvenance, provenance)
	if err != nil {
		return nil, err
	}
	return resolveCanonicalHistory(history, appliedCount), nil
}

func validateAppliedHistory(history *canonicalHistory, applied []appliedMigrationRecord, hasProvenance bool, provenance []appliedProvenanceRecord) (int, error) {
	if history == nil {
		return 0, fmt.Errorf("canonical migration history has no unambiguous provenance Foundation boundary")
	}
	if _, err := expectedRecordOrigin(history, history.provenanceFoundationIndex); err != nil {
		return 0, err
	}
	appliedCount, appliedByID, err := validateAppliedPrefix(history, applied)
	if err != nil {
		return 0, err
	}

	foundationApplied := history.provenanceFoundationIndex < appliedCount
	switch {
	case foundationApplied && !hasProvenance:
		return 0, fmt.Errorf("migration provenance table is missing although canonical migration %q is applied", history.entries[history.provenanceFoundationIndex].ID)
	case !foundationApplied && hasProvenance:
		return 0, fmt.Errorf("migration provenance table exists before canonical migration %q is applied", history.entries[history.provenanceFoundationIndex].ID)
	case !hasProvenance && len(provenance) != 0:
		return 0, fmt.Errorf("migration provenance records supplied without provenance table")
	case !hasProvenance:
		return appliedCount, nil
	}

	provenanceByID := make(map[string]appliedProvenanceRecord, len(provenance))
	positions := make(map[int64]string, len(provenance))
	for _, record := range provenance {
		if _, ok := provenanceByID[record.MigrationID]; ok {
			return 0, fmt.Errorf("duplicate applied migration provenance ID %q", record.MigrationID)
		}
		if previousID, ok := positions[record.CanonicalPosition]; ok {
			return 0, fmt.Errorf("duplicate applied migration provenance position %d for %q and %q", record.CanonicalPosition, previousID, record.MigrationID)
		}
		if _, ok := history.byID[record.MigrationID]; !ok {
			return 0, fmt.Errorf("unknown applied migration provenance ID %q", record.MigrationID)
		}
		provenanceByID[record.MigrationID] = record
		positions[record.CanonicalPosition] = record.MigrationID
	}
	if len(provenanceByID) != appliedCount {
		return 0, fmt.Errorf("applied migration provenance count %d does not match applied migration count %d", len(provenanceByID), appliedCount)
	}

	for index := 0; index < appliedCount; index++ {
		expected := history.entries[index]
		record, ok := provenanceByID[expected.ID]
		if !ok {
			return 0, fmt.Errorf("applied migration %q is missing durable provenance", expected.ID)
		}
		expectedOrigin, err := expectedRecordOrigin(history, index)
		if err != nil {
			return 0, err
		}
		if err := validateAppliedProvenanceRecord(expected, record, appliedByID[expected.ID].AppliedAt, expectedOrigin); err != nil {
			return 0, err
		}
	}

	return appliedCount, nil
}

func validateAppliedPrefix(history *canonicalHistory, applied []appliedMigrationRecord) (int, map[string]appliedMigrationRecord, error) {
	appliedByID := make(map[string]appliedMigrationRecord, len(applied))
	for _, record := range applied {
		if _, ok := appliedByID[record.ID]; ok {
			return 0, nil, fmt.Errorf("duplicate applied migration ID %q", record.ID)
		}
		if _, ok := history.byID[record.ID]; !ok {
			return 0, nil, fmt.Errorf("unknown applied migration ID %q", record.ID)
		}
		appliedByID[record.ID] = record
	}

	appliedCount := 0
	missingID := ""
	for _, entry := range history.entries {
		_, isApplied := appliedByID[entry.ID]
		if !isApplied {
			if missingID == "" {
				missingID = entry.ID
			}
			continue
		}
		if missingID != "" {
			return 0, nil, fmt.Errorf("applied migration history has a gap at %q before later migration %q", missingID, entry.ID)
		}
		appliedCount++
	}
	return appliedCount, appliedByID, nil
}

func validateAppliedProvenanceRecord(expected canonicalMigration, record appliedProvenanceRecord, appliedAt sql.NullTime, expectedOrigin string) error {
	mismatch := func(field string, actual, wanted any) error {
		return fmt.Errorf("applied migration provenance mismatch for %q field %s: got %v, expected %v", expected.ID, field, actual, wanted)
	}
	source, err := parseCanonicalSourceBinding(record.SourceBinding)
	if err != nil {
		return fmt.Errorf("applied migration provenance mismatch for %q field source_binding: %w", expected.ID, err)
	}
	if err := validateProvenanceSourceKind(record.ProvenanceClass, source.Kind); err != nil {
		return fmt.Errorf("applied migration provenance mismatch for %q field provenance_class/source_binding: %w", expected.ID, err)
	}

	if record.CanonicalPosition != expected.Position {
		return mismatch("canonical_position", record.CanonicalPosition, expected.Position)
	}
	if record.MigrationName != expected.Name {
		return mismatch("migration_name", record.MigrationName, expected.Name)
	}
	if record.ProvenanceClass != expected.Provenance {
		return mismatch("provenance_class", record.ProvenanceClass, expected.Provenance)
	}
	if record.OriginalMigrationID != expected.OriginalID {
		return mismatch("original_migration_id", record.OriginalMigrationID, expected.OriginalID)
	}
	if record.ContentSHA256 != expected.SHA256 {
		return mismatch("content_sha256", record.ContentSHA256, expected.SHA256)
	}
	if record.SourceBinding != expected.SourceBinding {
		return mismatch("source_binding", record.SourceBinding, expected.SourceBinding)
	}
	if record.BundleID != expected.BundleID {
		return mismatch("bundle_id", record.BundleID, expected.BundleID)
	}
	if record.PredecessorID.Valid != (expected.PredecessorID != "") || record.PredecessorID.String != expected.PredecessorID {
		return mismatch("predecessor_migration_id", nullStringValue(record.PredecessorID), expected.PredecessorID)
	}
	if record.DependencyEvidence != expected.DependencyEvidence {
		return mismatch("dependency_evidence", record.DependencyEvidence, expected.DependencyEvidence)
	}
	if record.AdaptationEvidence != expected.AdaptationEvidence {
		return mismatch("adaptation_evidence", record.AdaptationEvidence, expected.AdaptationEvidence)
	}
	if record.RecordOrigin != expectedOrigin {
		return mismatch("record_origin", record.RecordOrigin, expectedOrigin)
	}
	if record.AppliedAt.Valid != appliedAt.Valid || (record.AppliedAt.Valid && !record.AppliedAt.Time.Equal(appliedAt.Time)) {
		return mismatch("applied_at", nullTimeValue(record.AppliedAt), nullTimeValue(appliedAt))
	}
	return nil
}

func readAppliedMigrationRecords(ctx context.Context, conn *pgx.Conn) ([]appliedMigrationRecord, error) {
	rows, err := conn.Query(ctx, `select id, applied_at from gorp_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read applied migrations: %w", err)
	}
	defer rows.Close()

	var records []appliedMigrationRecord
	for rows.Next() {
		var record appliedMigrationRecord
		if err := rows.Scan(&record.ID, &record.AppliedAt); err != nil {
			return nil, fmt.Errorf("scan applied migration: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applied migrations: %w", err)
	}
	return records, nil
}

func provenanceTableExists(ctx context.Context, conn *pgx.Conn) (bool, error) {
	var exists bool
	err := conn.QueryRow(ctx, `select to_regclass(current_schema() || '.ms_oncall_migration_provenance') is not null`).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("detect migration provenance table: %w", err)
	}
	return exists, nil
}

func readAppliedProvenanceRecords(ctx context.Context, conn *pgx.Conn) ([]appliedProvenanceRecord, error) {
	rows, err := conn.Query(ctx, `
		select canonical_position, migration_id, migration_name, provenance_class,
			original_migration_id, content_sha256, source_binding, bundle_id,
			predecessor_migration_id, dependency_evidence, adaptation_evidence,
			record_origin, applied_at
		from ms_oncall_migration_provenance
	`)
	if err != nil {
		return nil, fmt.Errorf("read applied migration provenance: %w", err)
	}
	defer rows.Close()

	var records []appliedProvenanceRecord
	for rows.Next() {
		var record appliedProvenanceRecord
		if err := rows.Scan(
			&record.CanonicalPosition,
			&record.MigrationID,
			&record.MigrationName,
			&record.ProvenanceClass,
			&record.OriginalMigrationID,
			&record.ContentSHA256,
			&record.SourceBinding,
			&record.BundleID,
			&record.PredecessorID,
			&record.DependencyEvidence,
			&record.AdaptationEvidence,
			&record.RecordOrigin,
			&record.AppliedAt,
		); err != nil {
			return nil, fmt.Errorf("scan applied migration provenance: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applied migration provenance: %w", err)
	}
	return records, nil
}

func recordAppliedProvenance(ctx context.Context, conn *pgx.Conn, history *canonicalHistory, migrationID string) error {
	index, ok := history.indexByID(migrationID)
	if !ok {
		return fmt.Errorf("record provenance for unknown canonical migration %q", migrationID)
	}

	if index == history.provenanceFoundationIndex {
		applied, err := readAppliedMigrationRecords(ctx, conn)
		if err != nil {
			return err
		}
		appliedCount, appliedByID, err := validateAppliedPrefix(history, applied)
		if err != nil {
			return err
		}
		if appliedCount != index+1 {
			return fmt.Errorf("provenance Foundation migration bootstrap observed %d applied migrations, expected %d", appliedCount, index+1)
		}
		for entryIndex := 0; entryIndex < appliedCount; entryIndex++ {
			origin, err := expectedRecordOrigin(history, entryIndex)
			if err != nil {
				return err
			}
			entry := history.entries[entryIndex]
			if err := insertAppliedProvenance(ctx, conn, entry, appliedByID[entry.ID].AppliedAt, origin); err != nil {
				return err
			}
		}
		return nil
	}

	if index < history.provenanceFoundationIndex {
		return nil
	}
	origin, err := expectedRecordOrigin(history, index)
	if err != nil {
		return err
	}
	var appliedAt sql.NullTime
	if err := conn.QueryRow(ctx, `select applied_at from gorp_migrations where id = $1`, migrationID).Scan(&appliedAt); err != nil {
		return fmt.Errorf("read applied timestamp for canonical migration %q: %w", migrationID, err)
	}
	return insertAppliedProvenance(ctx, conn, history.entries[index], appliedAt, origin)
}

func expectedRecordOrigin(history *canonicalHistory, entryIndex int) (string, error) {
	if history == nil || history.provenanceFoundationIndex < 0 || history.provenanceFoundationIndex >= len(history.entries) {
		return "", fmt.Errorf("canonical migration history has no unambiguous provenance Foundation boundary")
	}
	if entryIndex < 0 || entryIndex >= len(history.entries) {
		return "", fmt.Errorf("canonical migration index %d is outside provenance Foundation history", entryIndex)
	}
	// Origin records how immutable evidence entered the ledger, not an
	// unknowable historical execution mechanism. The manifest's designated
	// Foundation identity makes this boundary stable across restarts and future
	// appended bundles.
	if entryIndex < history.provenanceFoundationIndex {
		return recordOriginPreLedgerBootstrap, nil
	}
	return recordOriginCanonical, nil
}

func insertAppliedProvenance(ctx context.Context, conn *pgx.Conn, entry canonicalMigration, appliedAt sql.NullTime, origin string) error {
	var predecessor any
	if entry.PredecessorID != "" {
		predecessor = entry.PredecessorID
	}
	var appliedAtValue any
	if appliedAt.Valid {
		appliedAtValue = appliedAt.Time
	}
	_, err := conn.Exec(ctx, `
		insert into ms_oncall_migration_provenance (
			canonical_position, migration_id, migration_name, provenance_class,
			original_migration_id, content_sha256, source_binding, bundle_id,
			predecessor_migration_id, dependency_evidence, adaptation_evidence,
			record_origin, applied_at
		) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`,
		entry.Position,
		entry.ID,
		entry.Name,
		entry.Provenance,
		entry.OriginalID,
		entry.SHA256,
		entry.SourceBinding,
		entry.BundleID,
		predecessor,
		entry.DependencyEvidence,
		entry.AdaptationEvidence,
		origin,
		appliedAtValue,
	)
	if err != nil {
		return fmt.Errorf("record applied migration provenance for %q: %w", entry.ID, err)
	}
	return nil
}

func deleteAppliedProvenance(ctx context.Context, conn *pgx.Conn, history *canonicalHistory, migrationID string) error {
	index, ok := history.indexByID(migrationID)
	if !ok {
		return fmt.Errorf("delete provenance for unknown canonical migration %q", migrationID)
	}
	exists, err := provenanceTableExists(ctx, conn)
	if err != nil {
		return err
	}
	if !exists {
		if index <= history.provenanceFoundationIndex {
			return nil
		}
		return fmt.Errorf("migration provenance table disappeared while rolling back %q", migrationID)
	}

	tag, err := conn.Exec(ctx, `delete from ms_oncall_migration_provenance where migration_id = $1`, migrationID)
	if err != nil {
		return fmt.Errorf("delete applied migration provenance for %q: %w", migrationID, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("delete applied migration provenance for %q affected %d rows, expected 1", migrationID, tag.RowsAffected())
	}
	return nil
}

func nullStringValue(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}

func nullTimeValue(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return value.Time
}
