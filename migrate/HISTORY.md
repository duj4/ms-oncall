# Canonical migration history

`history.json` is the reviewed source of truth for migration execution order and
provenance. The migration runner does not derive execution order from directory
or filename sorting. Each bundle declares its first canonical position, source
binding, adaptation evidence, and exact dependency on the preceding bundle. Its
ordered entry list expands deterministically into per-migration positions and
predecessors.

Every entry binds an executable migration ID, its original source identity, and
the SHA-256 digest of the exact embedded SQL bytes. The accepted digest lives in
`history.json`; runtime validation computes the SQL digest only for comparison.
It never regenerates or accepts a checksum from the SQL file itself. Missing,
extra, duplicate, reordered, or modified migrations fail validation before any
database migration is attempted.

Existing accepted entries, source bindings, positions, and checksums are
append-only. A future adopted GoAlert release or MS OnCall forward fix is added
as a new bundle after the current tail, with an exact predecessor binding. An
already applied entry is never inserted ahead of, renumbered within, or edited
in the canonical sequence.

## Source binding without commit self-reference

Upstream bundles bind to the adopted GoAlert release and exact source commit.
The first MS OnCall bundle binds to the exact owner-authorized Project commit
and tree, the exact Core parent commit and tree, the checkpoint identity, and
the migration content checksum. It deliberately does not claim the future Git
commit that introduces itself. The resulting Core commit binds the reviewed
manifest and SQL together after validation, without an impossible attempt to
embed its own commit hash.

## Applied history

`gorp_migrations` remains the execution compatibility record and is never
rewritten during bootstrap. Migration
`20260830195814-ms-oncall-migration-provenance.sql` additively creates
`ms_oncall_migration_provenance`. In the same migration transaction, the runner
records the exact canonical metadata and original `applied_at` value for every
applied migration. `record_origin` describes the observable way that the row
entered this ledger; it does not claim how the migration SQL was historically
executed:

- canonical positions before the explicitly designated
  `provenance_foundation_migration_id` are recorded as
  `PRE_LEDGER_BOOTSTRAP`, because their valid `gorp_migrations` rows necessarily
  exist before the ledger becomes authoritative;
- the designated Foundation position and every later appended canonical entry
  are recorded as `CANONICAL_EXECUTION`, because their provenance is recorded
  while the ledger is authoritative.

This manifest identity is the permanent pre-ledger/post-ledger boundary. It is
not recomputed from the number of rows found at process startup, and appending a
future bundle does not move it. Consequently, an existing GoAlert database and
a fresh canonical install that reach the same pre-Foundation history receive
the same observable origin classification, including after an interrupted
fresh install or a Foundation rollback/reapply.

After that foundation is applied, the `gorp_migrations` prefix and durable
provenance ledger must agree exactly on identity, position, checksum, source,
predecessor, dependency/adaptation evidence, origin, and applied time. Unknown,
gapped, incorrectly classified, or contradictory state fails closed. The
Foundation DDL, its `gorp_migrations` insert, the complete pre-ledger bootstrap,
and its own provenance row commit in one PostgreSQL transaction. An interruption
before commit therefore leaves none of those Foundation-owned effects; after a
successful commit they are all present. Unsupported durable partial states fail
closed instead of being normalized. Rolling back the Foundation transactionally
drops only its additive ledger and its own `gorp_migrations` row; historical
rows are left unchanged.

`DumpMigrations` exports both the canonical manifest and the SQL files. The SQL
must be applied through this Core migration runner so ledger bootstrap and
per-entry provenance recording remain atomic with `gorp_migrations` updates.

`migrate/schema.sql` is generated with the repository's `make db-schema`
workflow after migration changes. Do not maintain it manually.

This foundation contains no Organization persistence or authorization behavior.
