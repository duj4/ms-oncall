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

Manifest object keys are a strict canonical contract. Every key must use the
exact lowercase spelling documented by `history.json`; exact duplicates,
case-folded aliases, and unknown fields at the manifest, bundle, source,
dependency, and migration-entry levels are rejected before typed decoding or
database planning. A later JSON value can therefore never override an earlier
logical field through `encoding/json` case-insensitive field matching.

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

Provenance ownership and source kind form a closed compatibility matrix:
`UPSTREAM_GOALERT` uses only `GOALERT_RELEASE`, and `MS_ONCALL` uses only
`MS_ONCALL_CHECKPOINT_BASE`. Both pairings retain complete source metadata;
cross-pairings and unknown kinds fail before migration planning. Durable source
bindings are parsed and checked against the same matrix before the ledger is
accepted.

An MS OnCall adaptation or forward fix of an upstream migration remains owned
by `MS_ONCALL` and is sourced from its owner-authorized
`MS_ONCALL_CHECKPOINT_BASE`; it is not mislabeled as upstream provenance. The
bundle's exact `depends_on` predecessor identifies the adopted upstream
dependency, and the required `adaptation_evidence` states the reviewed
adaptation or forward-fix relationship. Missing dependency or adaptation
evidence fails closed.

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

## Canonical position 276: Organization persistence foundation

Bundle `ms-oncall-organization-default-persistence-foundation-v1` appends one
MS OnCall migration at canonical position 276:
`20260901100808-ms-oncall-organization-persistence.sql`, exact SHA-256
`4551270e716d9dd6572dbde7173b6d7a15a3510f11045e770d5f51c80dbfdc5f`.
It binds to Core base commit
`53393ce48da36c2185c36b92ac5393f8658bf7e7`, base tree
`c7bbe26f003a286d9fe162a4313d4d9acff874ec`, and Project authorization commit
`83ce1e292f6db1cbb6d89287a1614fd14cada482`, authorization tree
`1c7950b46e50fdf31eeb2cbaf04c98205237fe68`.

The bundle depends exactly on accepted bundle
`ms-oncall-migration-provenance-history-foundation-v1`, migration
`20260830195814-ms-oncall-migration-provenance.sql`, checksum
`c22fb8e6bd4fe90788d5c0f6b9dd8ecb4cce43658ffa79691311c3846df0db5e`.
Its dependency evidence records that it appends after the accepted Migration
Provenance & Combined History Foundation V1. Its adaptation evidence identifies
the migration as an additive MS OnCall Organization persistence foundation,
not an upstream GoAlert migration. The permanent
`provenance_foundation_migration_id` remains unchanged, so position 276 records
origin `CANONICAL_EXECUTION`.

The migration adds a stable Organization UUID, `NORMAL` / `DEFAULT`
classification, mutable display identity, immutable canonical identity,
`ACTIVE` / `SUSPENDED` / `RETIRED` lifecycle, and non-null creation/update audit
timestamps. A relational one-to-one `normal_organizations` subtype can reference
only a `NORMAL` base and carries an immutable globally unique corporate mapping
key plus a canonical IANA time-zone name. Future operational-owner foreign keys
can target this subtype; this checkpoint adds no such foreign key to a production
operational table.

The distinguished Default Organization is inserted without conflict suppression
using deterministic UUID `296e2656-7221-53fe-bd0a-832d24ccfd03`, canonical
identity `ms-oncall.default`, display identity `Default Organization`, and
lifecycle `ACTIVE`. Database constraints and triggers prevent a second Default,
Default deletion, Default subtype creation, immutable identity/classification
changes, corporate mapping-key changes, and invalid lifecycle transitions.
Supported time-zone writes use Core's existing canonical zone mapping. Store
writes create base/subtype atomically and expose no generic Default creation or
hard-delete method.

All position 276 application objects and trigger targets are explicitly bound
to schema `public`. Each of its three PL/pgSQL trigger functions has exact
function configuration `search_path=pg_catalog, pg_temp`, uses no
`SECURITY DEFINER`, and schema-qualifies every application-object reference.
Consequently neither a caller-controlled schema before `public` nor an implicit
temporary schema can redirect the NormalOrganization audit touch away from
`public.organizations`. Down migration object resolution is likewise explicitly
bound to `public` and cannot remove an identically named shadow object.

Trigger-generated rejections use SQLSTATE `23514` with stable, semantic
constraint identities and structured `public` schema/table/column metadata.
The identities distinguish base UUID, classification, canonical identity, and
creation-time immutability; distinguished Default lifecycle and deletion;
normal lifecycle transitions; NormalOrganization subtype identity and
classification; corporate mapping-key immutability; and the subtype/base
invariant. PostgreSQL tests compare exact SQLSTATE, constraint, schema, table,
column, and datatype metadata for each trigger and declarative invariant, then
verify the transaction rollback and durable state. Store classification is
limited to known constraint identities and preserves the original PostgreSQL
error for diagnostic unwrapping.

Focused validation covers fresh installation, Foundation-only upgrade,
Foundation and new-tail rollback/reapply, unsupported partial schema state,
deterministic Default bootstrap, relational/immutable constraints, concurrent
mapping-key creation, store lookups and updates, lifecycle transitions, IANA
time-zone canonicalization, canonical provenance origin, and migration smoke
snapshot equivalence. The generated schema is produced twice by `make
db-schema` and must remain byte-identical on the second run.

The highest valid capability claim is: **Organization identity persistence
foundation exists.** This position does not implement UserOrganizationAssignment,
ordinary User selection, Organization authorization/isolation, operational
`organization_id`, GraphQL/API/UI behavior, or Organization-aware Engine work.

## Canonical position 277: UserOrganizationAssignment persistence foundation

Bundle `ms-oncall-user-organization-assignment-persistence-foundation-v1`
appends one MS OnCall migration at canonical position 277:
`20260901220323-ms-oncall-user-organization-assignment-persistence.sql`, exact
SHA-256
`b9bbade729665431c23c74c689aa90f1c0ba484678026b6a6398b649f0e21b8e`.
It binds to Core base commit
`7e698840ee69eb04c84e19830221b4637be435c6`, base tree
`4c2d01c2cdf2785a78d423e0b32258c9b6d7a212`, and Project authorization
publication commit `de12830b9c2da4c4a2d71020cf4374f76cfdb7cf`, authorization
tree `22aa6f10bb7fe3cbea306a250513e48caec50335`.

The bundle depends exactly on accepted bundle
`ms-oncall-organization-default-persistence-foundation-v1`, migration
`20260901100808-ms-oncall-organization-persistence.sql`, checksum
`4551270e716d9dd6572dbde7173b6d7a15a3510f11045e770d5f51c80dbfdc5f`.
Its dependency evidence records that it appends only after the accepted
Organization / NormalOrganization / Default persistence foundation. Positions
1 through 276 remain unchanged, and the permanent provenance-Foundation
boundary remains position 275.

The migration adds at most one explicitly persisted
`UserOrganizationAssignment` row per global User. The row contains an explicit
effective Organization identity and classification; `NULL` never represents
Default. `EXACTLY_ONE` requires an explicit non-NULL subtype identity equal to
the effective Organization and relationally verified by the
`normal_organizations` foreign key, plus `ORG_MEMBER` or `ORG_ADMIN`. `ZERO`
and `MULTIPLE` require the distinguished Default Organization and `NONE`;
their matched counts are respectively zero and greater than one. Assignment
state is limited to `ACTIVE` and `TRANSITIONING`, and a non-nil
pending-transfer identity is valid only while `TRANSITIONING`.

Required authoritative evaluation evidence consists of a finite timestamp,
non-blank source/config version, matched count, and non-zero 32-byte SHA-256
digest. Source/config versions reject the same fixed Unicode White_Space set
at either boundary in Go and PostgreSQL, and matched counts outside the
PostgreSQL `integer` range fail Go validation before SQL. No raw
identity-provider claims are persisted. Generation begins at one for
store-created rows. Database truth requires state changes to use a higher
generation, rejects generation decrease, and requires every evidence write to
advance the authoritative evaluation time. The internal store uses an
expected-generation compare-and-swap for replacement and permits a guarded
unchanged-assignment evidence refresh without advancing generation.

The update trigger is explicitly bound to `public`, has fixed
`search_path=pg_catalog, pg_temp`, uses no `SECURITY DEFINER`, and resolves no
application object through ambient search path. Declarative foreign keys and
checks continuously bind effective normal identities to
`public.normal_organizations`, Default to its distinguished UUID, and each row
to its global User. Trigger rejections use stable SQLSTATE `23514` constraint,
schema, table, and column identities.

No existing User is backfilled, and no User-creation trigger or application
hook creates an assignment. The migration and store do not implement a mapping
resolver, identity-provider integration, login/session/permission/RBAC behavior,
transfer execution, operational-resource ownership, GraphQL/API/UI surfaces,
Engine work, Gateway integration, or production readiness.

The highest valid capability claim is:
**UserOrganizationAssignment additive persistence foundation exists for
explicitly persisted rows.**

## Canonical position 278: Human security generation persistence foundation

Bundle `ms-oncall-human-security-generation-persistence-foundation-v1`
appends one MS OnCall migration at canonical position 278:
`20260903184951-ms-oncall-human-security-generation-persistence.sql`, exact
SHA-256
`442b919a8b001b9cf6ea1a118b0a5ebe7d6b674483ca867e1c264efb7e854d16`.
It binds to Core base commit
`bbdaebfe27a74643e8cdd03d27845ff76e69771b`, base tree
`364ad3fa042b186c3e32b3ee3e4bc25f529c925e`, and Project authorization
commit `3a7bd58b9d1a3c5e866b402f6600e9e416ae2705`, authorization tree
`588b843dd81fb81cdd2ce2aa3e30464bfdb05e10`.

The bundle depends exactly on accepted bundle
`ms-oncall-user-organization-assignment-persistence-foundation-v1`, migration
`20260901220323-ms-oncall-user-organization-assignment-persistence.sql`,
checksum
`b9bbade729665431c23c74c689aa90f1c0ba484678026b6a6398b649f0e21b8e`.
Its dependency evidence records that it appends only after the accepted
UserOrganizationAssignment persistence foundation. Positions 1 through 277
remain unchanged, and the permanent provenance-Foundation boundary remains
position 275.

The migration adds at most one explicitly persisted human security generation
row per global User. Generation begins at one. There is no migration backfill,
User-creation trigger, login hook, or missing-state fallback. The database
rejects non-one inserts, User identity mutation, unchanged or decreasing
generation, skipped generation, and advancement past the PostgreSQL `bigint`
maximum. The only accepted update advances generation by exactly one. Deleting
the global User cascades its sidecar row.

The invariant trigger is explicitly bound to `public`, has fixed
`search_path=pg_catalog, pg_temp`, uses no `SECURITY DEFINER`, and resolves no
application object through ambient search path. Trigger rejections use stable
SQLSTATE `23514` constraint, schema, table, and column identities.

The additive internal User Store seam supports only explicit create, read, and
expected-generation guarded advance. Loaded zero, negative, or nil-identity
state fails closed. A missing row remains NotFound, a stale guarded write is
not retried, and `math.MaxInt64` is rejected before increment SQL is issued.
Existing `users.role` writes neither create nor advance this sidecar state.

This position adds no session persistence, issuance, revocation, authentication
or OIDC wiring, runtime consumer, ExecutionContext construction, role or
privilege coupling, PlatformAdmin grant or assumption semantics, authorization
effect, API, GraphQL, UI, Engine behavior, or Gateway behavior.

The highest valid capability claim is: **Human security generation additive
persistence foundation exists for explicitly persisted rows.**
