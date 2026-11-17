// Package postgres collects deletion facts using a caller-owned PostgreSQL
// transaction. It never owns a transaction or performs a business mutation.
//
// Preview requires a read-only repeatable-read (or serializable) transaction.
// Recheck uses the same read implementation in an owning transaction; it does
// not implement deletion enforcement, locking, or JSON writer cooperation.
// Neither a preview nor its fingerprint authorizes a later mutation.
//
// Collect first corroborates canonical admitted Human evidence (or compiled
// internal System authority), resolves the actual target/Organization/owner,
// and calls a mandatory server-selected AuthorizeFacts callback. Scope equality
// is not operation permission. The callback must use read-only authorization
// helpers and respect the supplied deadline; its own queries need a caller
// budget. Target selectors and callbacks must never be deserialized together
// from a client request. Ordinary Human reads remain within their Normal Home;
// unsupported principal modes fail closed rather than gaining global access.
//
// Every collection uses one server statement_timestamp observation. Native
// UserOverride rechecks share one post-lock database observation across the
// entire batch; locks stabilize rows, never the passage of time. Preview uses
// its own observation and a changed lifecycle invalidates its ImpactVersion.
// Collection uses keyset
// pages, typed/indexable FK predicates, per-kind batched identity resolution,
// and raw pre-deduplication budgets. Checked coverage includes every object
// actually admitted to the frozen policy's removal closure. Empty final pages,
// Rows.Err, malformed JSON, missing parents, owner mismatches and exhausted
// budgets are not interpreted as complete empty scans. No labels, destinations,
// credential selectors, subjects, payloads or raw provider data are returned.
// Failure returns no partial rows, counts, coverage, or scope fingerprint.
// Internal completeness flags are diagnostics, not a wire error contract.
//
// Known schema boundaries without an accepted V1 mapping stop the affected
// projection: labels, heartbeat children, provider compatibility rows, universal
// key config and calendar credentials. A Rotation root admits its complete
// Participant/State closure only for consistent version-2 runtime and scoped
// Users; historical or malformed State and other roots' runtime remain closed. A raw
// TemporarySchedule shift with an empty effective intersection is Unsupported:
// V1 cannot represent that interval without inventing a PeriodState. Unknown
// JSON members are detected before the SQL projection strips their values.
// None of these cases changes a frozen product rule or publishes Complete.
//
// Raw User scans inspect every schedule_data envelope because a foreign or
// malformed row cannot safely be ruled out by a normal Schedule getter or an
// authorized-only filter. Only matching, authorized User edges are published.
// Unrelated envelopes consume the same internal deadline/byte/fragment budget;
// their counts are never returned. Ordinary Human failures of this global JSON
// scan are generic Unavailable, including budget exhaustion, to avoid exposing
// foreign scan size. Global System reads retain the typed limit error.
//
// Limits bound Go materialization and overall query time. PostgreSQL may still
// detoast/sort/scan existing rows while evaluating byte guards and predicates;
// this adapter does not establish a production memory or latency SLA. Reverse
// User/Rotation FK scans and raw JSON scans may use sequential scans with the
// current indexes. Review EXPLAIN (ANALYZE, BUFFERS) on disposable fixtures before
// tuning: action-to-step/policy, rule-to-schedule, participant-to-rotation,
// outgoing-message FKs, and schedule_data.id pagination. Do not add an index or
// migration solely to force a particular plan on a small fixture.
package postgres
