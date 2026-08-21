# Core Gateway Destination Token Rotation Coordinator V1

## Status and boundary

This checkpoint adds a transport-independent, System-only Core outer
coordinator. It is a domain and persistence-boundary foundation only. It is not
wired to HTTP, RPC, GraphQL, the UI, a CLI, startup, a scheduler, or automatic
cleanup, and it does not enable Gateway runtime delivery.

Core remains the sole owner of the Contact Method destination. Gateway remains
the sole owner of destination-token creation, resolution, exact-record
identification, lifecycle transitions, rollback, and revocation. The
coordinator uses narrow injected ports and never imports or accesses Gateway
persistence. Gateway never accesses Core persistence. No cross-database SQL,
shared connection, or distributed transaction is used.

The public start request, participant request and response values, observation,
continuation handle, coordinator result, authoritative destination wrapper, and
service all format as `[redacted]`. Fixed errors contain no URL, token,
verifier, key or record ID, SQL, database setting, host, account, or dependency
error. The returned continuation handle contains the Core Contact Method UUID
and a defensively copied opaque participant handle; it contains no complete URL
or raw old/new token.

## Participant contract

The Core port mirrors the Gateway participant's bounded protocol:

- `BeginRotation` receives the validated audience, destination, and current
  raw token. A confirmed success means Gateway has already committed the exact
  new-active/old-retiring pair and returns one-time new-token material plus an
  exact-attempt handle, activation snapshot `A`, and immutable retirement
  deadline `G` actually persisted by that activation. Gateway constructs the
  receipt and activation command from the same `A` and `G`; adapters must not
  resample or recompute them. Core requires `0 < G-A <= 24h`. If Gateway cannot
  authoritatively obtain that exact receipt after activation, it returns only
  the handle with reconciliation required and zero token, `A`, and `G`.
- `ObserveRotation` is one operation, not separately callable identity and
  lifecycle ports. Gateway must first identify the candidate token against the
  exact attempt records, including revoked records, and then read the latest
  attempt-specific state. It returns only `new`, `old`, or `neither`,
  `active-with-retiring`, `rolled-back`, or `completed`. An active observation
  also carries one same-operation Gateway clock snapshot `O` and the attempt's
  authoritative `G`; terminal observations carry zero `O` and `G`.
- `RollbackRotation` and `FinalizeRotation` operate on the exact attempt
  handle. A stale, mismatched, or duplicate mutation is not success.
- Core sends only the fixed `deadline-elapsed` finalization reason. V1 has no
  caller-provided `drained` boolean and no early verified-and-drained path.

If Gateway Begin cannot prove cleanup after creating state, it may return a
handle-only attempt with an error. Any Begin error accompanied by a valid
handle is state-uncertain regardless of the error value: Core returns
`needs-reconciliation`, that redacted continuation handle, and its fixed
reconciliation-required error. It never downgrades such a result to invalid,
conflict, unavailable, canceled, or deadline, and never returns the failed
attempt's raw new token. This permits an explicit later reconciliation without
inventing a durable coordinator journal in this checkpoint.

Core and Gateway use the reviewed symbolic token identities `new`, `old`, and
`neither` with values 1, 2, and 3. Core's deadline-elapsed reason has value 2,
matching Gateway's accepted lifecycle reason. These numeric equalities are
contract drift guards, not a serialization mechanism: every future adapter
must map the named symbols explicitly and reject unknown values rather than
casting cross-repository or wire integers.

## Fixed start order

`Start` executes in this order:

1. require `permission.System` and a live context;
2. validate the complete canonical expected Gateway URL with the accepted
   strict `GatewayTargetMatcher` and extract only its final canonical token;
3. validate canonical audience and destination UUID bindings;
4. sample the local monotonic clock and call Gateway `BeginRotation`;
5. require the confirmed attempt's persisted receipt to satisfy
   `0 < G-A <= 24h`, then derive `localG = anchor + (G-A)`;
6. admit CAS only while `localG-now > C+D+R`;
7. consume the confirmed one-time new token in exactly one fenced form of the
   accepted token-only Core CAS: on one transaction and physical connection,
   lock the exact Contact Method row first, execute the existing conditional
   token-only `UPDATE` once, and then commit once;
8. on confirmed CAS success, return a redacted pending-finalization result and
   continuation handle.

Core never points to an unactivated token. It never retries Begin, regenerates
the token, retries or replays CAS, issues a second CAS, or immediately finalizes
the old token. The public production constructor requires the exact same matcher
instance used by the accepted CAS validator; equivalent-looking independent
configuration is rejected rather than allowed to drift.

The protocol budgets are `B=C=D=R=L=5s`: Begin, CAS, physical discard,
recovery/participant operation, and transaction-lock release reserve. Begin
uses the earlier of the caller deadline and the local absolute `anchor+B`.
Sampling immediately before Begin deliberately charges all Begin latency
against `localG`. Caller cancellation or deadline visible after a confirmed
Begin prevents CAS admission and permits only one detached but absolute-
deadline-bounded exact rollback.

The CAS absolute deadline is the earliest of the caller deadline, `now+C`, and
`localG-D-R`. Physical quarantine is allowed only until `CAS-deadline+D`;
unknown recovery and safe rollback are allowed only until
`min(now+R, localG)`. Admission requires strictly more than the complete
`C+D+R` window, so exactly 15 seconds remaining is rejected before CAS. A
confirmed pre-CAS rollback returns unavailable; an unconfirmed rollback or an
invalid receipt preserves the handle and requires reconciliation.

Core never compares Gateway wall-clock instants directly with its local wall
clock. It uses only `G-A` and, for an explicit active observation, `G-O`.
Each duration is added to a local monotonic sample taken immediately before the
corresponding Gateway call, so call latency consumes the remaining local
window. This tolerates a fixed Core/Gateway clock offset without extending the
authoritative interval. Gateway still authoritatively rejects any rollback or
finalization outside its persisted lifecycle rules.

V1 has no cross-host bounded-clock-skew or database commit lease, so it does not
claim that every ambiguous database commit is physically resolved before the
Gateway deadline. It proves the narrower safety property: Core stops admitting
new CAS work before the reserved cutoff; only an attempt whose physical
quarantine was confirmed may enter row-fenced recovery; later Core recovery,
rollback, and finalization serialize behind that fence; and a late new-token
resolution is kept pending rather than rolled back outside the overlap.

## CAS and compensation matrix

The accepted CAS classifications are used as evidence, not matched through
`errors.Is`. Only the exact, direct fixed sentinel is accepted as a safe
classification. Wrapped, joined, mixed, typed-nil, and unrecognized errors fail
closed.

| CAS result | Core action | Returned state |
| --- | --- | --- |
| Confirmed success | No rollback and no authoritative read | Pending finalization |
| Exact invalid, permission denied, conflict, confirmed unavailable, pre-statement canceled, or pre-statement deadline | One exact Gateway rollback using a fresh bounded context | Original safe fixed failure only if rollback is confirmed |
| Same safe result, but rollback fails, conflicts, or is uncertain | No retry or second compensation | Reconciliation required |
| Exact outcome unknown after physical quarantine is confirmed by its absolute deadline | No immediate rollback and no CAS retry; perform the serialized authoritative procedure below | Proven pending or safe restored failure; otherwise reconciliation required |
| Physical quarantine unconfirmed, joined/mixed, or unrecognized | Do not enter the authoritative callback and do not mutate Gateway | Reconciliation required with handle |

After a quarantined unknown CAS, only an exact current new token plus the exact
active pair and the same immutable `G` confirms pending finalization. An exact
current old token plus the exact pair and matching `G` permits one rollback;
confirmed rollback returns a fixed unavailable failure
because the attempted rotation is now proven not active. A third token,
non-Gateway or malformed destination, missing record, stable-but-unexpected
Gateway state, read/observation failure, or rollback failure returns
reconciliation required without another mutation. Once Begin has returned a
valid handle, every such reconciliation-required result carries
`needs-reconciliation` plus a defensive copy of that same continuation handle.
The only post-Begin failures returned without a reconciliation state are safe
CAS failures after exact rollback is confirmed, or other failures whose
contract itself proves no uncertain state.

Rollback is permitted only strictly before the conservatively derived local
deadline and still remains subject to Gateway's authoritative `G`. An old-token
observation at or after local expiry remains reconciliation required without
rollback. A new-token observation at or after local expiry is a legal late
resolution of the already-fenced CAS and remains pending
finalization; Core never tries to reverse it after overlap expiry.

## Fenced CAS and serialized authoritative Core read

A plain MVCC `SELECT` started only after an unknown autocommit CAS is
insufficient: it could read the old version before a delayed update reaches
PostgreSQL, rollback Gateway, and then be overtaken by that update. The
coordinator-specific production CAS therefore acquires a fresh
`database/sql.Conn`, begins one PostgreSQL `READ COMMITTED` transaction, and
reuses `ContactMethodFindOneUpdate` (`SELECT ... FOR UPDATE`) **before** it sends
the existing generated conditional `ContactMethodCompareAndSwapGatewayDest`
statement. The lock, exactly one `UPDATE`, and exactly one commit attempt share
that transaction and physical connection.

After a commit error or other outcome-unknown result, the physical connection
must be destroyed no later than absolute `CAS-deadline+D` before recovery
begins. If quarantine cannot be positively confirmed by that deadline, Core
returns reconciliation required and never invokes the recovery locking
callback. A fresh recovery connection then executes the same
`SELECT ... FOR UPDATE`. PostgreSQL row-lock ordering makes that read wait
until the earlier fenced transaction commits or rolls back; it cannot read the
old version and later be overtaken by the same attempt. If connection
destruction or the locking read cannot be confirmed, recovery returns
reconciliation required and performs no Gateway mutation.

For reconciliation and finalization, the adapter holds the fresh Core row lock
while the coordinator performs the one bounded Gateway observation and any
exact rollback or finalization, then confirms transaction rollback to release
the read fence. Lock queries and every Gateway call share an operation context
bounded to at most five seconds. The `database/sql` transaction uses a separate
caller-cancellation-detached context bounded to the operation's remaining time
plus a fixed five-second release reserve (at most ten seconds total). The pgx
stdlib transaction wrapper uses that Begin context for commit/rollback. This
prevents caller cancellation from making `database/sql` automatically release
the row lock in the middle of a conforming callback, while still bounding a
stuck transaction. The store derives the callback context itself with an
absolute deadline no later than `operation-anchor+R`; its transaction deadline
is exactly `operation-deadline+L`. The callback never detaches its mutation from
the shorter context. If that context has expired by explicit lock release, the
connection is discarded and the result remains reconciliation required even
when rollback returns nil.

The authoritative recovery transaction is logically read-only and executes no
`INSERT`, `UPDATE`, or `DELETE`. It is intentionally not declared SQL
`READ ONLY`, because PostgreSQL does not permit `SELECT ... FOR UPDATE` in a
read-only transaction. Any acquire, begin, scan, timeout, callback-contract, or
lock-release failure is reconciliation required and never ordinary canceled,
unavailable, conflict, or success.

Only post-Begin safe compensation and confirmed-quarantine unknown-CAS recovery
detach caller cancellation with `context.WithoutCancel`; both immediately gain
the absolute `min(now+R, localG)` deadline and preserve System permission.
Explicit `Reconcile` and `Finalize` honor their caller's earlier cancellation or
deadline. In every case the store derives a lock-scoped context of at most `R`,
and query, Observe, Rollback, and Finalize use only that context. If the row lock
or Gateway operation cannot finish inside the bound, Core preserves Gateway
state and returns reconciliation required.

`database/sql.Tx.Rollback` itself has no context parameter. The production pgx
wrapper applies the finite transaction context described above, but the code
does not generalize that as a hard wall-clock guarantee for arbitrary SQL
drivers. A rollback error, or a fenced-CAS rollback that returns only after its
operation context has expired, destroys the physical connection and remains
outcome-unknown/reconciliation-required; it is never downgraded to safe
no-mutation evidence. This favors ordering and honest state over a false timeout
claim.

After a physical Core connection has been acquired, any `BeginTx` error or
nil/typed-nil transaction discards that physical connection before returning.
Query failures require confirmed rollback before reuse; any rollback error,
including an unexpected already-done transaction, also discards the connection
and returns reconciliation required.

Holding the Core row lock serializes this trusted coordinator's single fenced
CAS with its later observation/compensation decision. It does not by itself
neutralize a second or bypass replay queued on another connection. Gateway's
destination serialization and exact record pair prevent a concurrent or stale
participant handle from overwriting newer lifecycle state. This is not a
cross-database atomic transaction: a failure after one side's confirmed
mutation is represented honestly and must be re-observed.

Every connection used by the fenced update and every later authoritative lock
must route to the same linearizable writable PostgreSQL primary. A read replica,
multi-primary topology, or non-linearizable/uncertain failover is outside this
seam's safety proof; the connection provider must fail closed in that condition,
which yields reconciliation required before any callback or Gateway rollback.
Unit tests prove statement order, callback lock lifetime, and fault
classification only. No real PostgreSQL interruption, replication, HA, or
failover behavior is claimed without a dedicated configured environment.

The fence also assumes the trusted coordinator is the only issuer of this
attempt's one-time old-to-new CAS and that it never retries or replays it. A
second or bypass replay carrying the secret new token could queue behind the row
lock and commit after recovery rolls Gateway back; preventing a malicious or
duplicated out-of-band issuer would require a durable attempt/version fence,
which is outside V1. The new token is confined to the trusted participant result
and the exactly-once coordinator call.

## Explicit reconciliation

`Reconcile` is repeatable but does not turn a stale request into idempotent
success. Under the serialized Core read it performs exactly one combined
Gateway observation:

| Core token identity | Exact Gateway attempt state | Action/result |
| --- | --- | --- |
| New | Active with retiring | Pending finalization |
| Old | Active with retiring, strictly before the valid deadline | One exact rollback; confirmed result is rolled back |
| Old | Active with retiring, at/after or beyond the bounded deadline | Reconciliation required; no rollback |
| Old | Rolled back to exact old-active stable state | Rolled back, without another mutation |
| New | Completed with exact new-active and finalized old token | Completed, without another mutation |
| Any other combination | Any | Reconciliation required, no mutation |

Concurrent reconciliations serialize on the Core row. After the first confirms
rollback, later calls observe the exact stable rolled-back attempt and do not
repeat the mutation.

For an active pair, Core samples its local monotonic clock immediately before
`ObserveRotation` and derives conservative `localG = anchor + (G-O)`. Time spent
inside Observe is therefore charged to the window. Terminal observations carry
zero `O/G` and require the exact stable token/state combination shown above.

## Deadline-only finalization

`Finalize` takes only the continuation handle. Under the same Core row lock it
must prove all of the following:

- Core's complete canonical destination contains the exact new attempt token;
- Gateway reports the exact new-active/old-retiring pair;
- local monotonic time is at or after `anchor + (G-O)`, using the sample taken
  immediately before the same active observation.

Before the deadline it returns the fixed too-early error. At or after the
deadline it calls Gateway once with the fixed deadline-elapsed reason. A
confirmed result is completed. A stale pair, old or third Core token, duplicate
finalization, conflict, ambiguous mutation, or unknown dependency result is not
success. There is no scheduler or automatic finalization in V1.

## Deferred production work

This foundation deliberately does not persist, serialize, or transport the
continuation handle. A future authorized operational composition must provide a
trusted way to retain and resubmit the redacted handle before it invokes these
mutation methods; this checkpoint does not claim crash recovery for a caller
that discards it. The bounded contexts and physical-discard protocol establish
live-process fail-closed safety decisions; they do not claim liveness after a
process crash, a driver that ignores deadlines, or an unavailable/uncertain
PostgreSQL topology. HTTP authentication/resolution composition, runtime wiring,
durable orchestration, automated scheduling, provider delivery, callbacks,
DTMF/ACK, production secret sources, schema changes, and migrations remain
outside this checkpoint.
