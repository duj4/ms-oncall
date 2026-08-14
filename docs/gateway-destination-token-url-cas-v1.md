# Gateway Destination Token-only URL CAS V1

## Status and boundary

This foundation is an internal Core operation. It is not connected to HTTP,
GraphQL, the UI, startup wiring, or any automatic rotation coordinator. It
does not configure Gateway credentials and does not enable production token
rotation.

The operation accepts an opaque request containing:

- one non-zero Contact Method UUID;
- the expected complete Gateway destination URL; and
- one replacement raw opaque token.

The service is constructed with the already-approved strict
`GatewayTargetMatcher`. It never accepts an arbitrary replacement URL. The
replacement URL is built internally by changing only the final token segment
of the validated expected URL and is then independently validated by the same
matcher. This preserves all other bytes, including an explicitly written
canonical HTTPS port.

Both the request and service format as `[redacted]`. Expected and replacement
URLs, tokens, generated destinations, SQL parameters, and database errors must
not be logged, traced, used as metric labels, or returned to callers.

## Validation and permission

The expected URL must be a canonical target at the configured HTTPS Gateway
origin, with the exact contact-method path, no user information, query,
fragment, encoded path, alternate spelling, or suffix. Both old and
replacement tokens must use the canonical unpadded base64url form and decode
to exactly 32 bytes. The replacement token must differ from the old token.

Only a `permission.System` context may call the operation. Unauthenticated,
normal-user, administrator, service, and team contexts are rejected before any
repository or database operation. Ordinary Contact Method updates continue to
reject every destination change.

## Atomic PostgreSQL update

The PostgreSQL adapter obtains one dedicated `database/sql.Conn` and executes
one generated, parameterized conditional update:

```sql
UPDATE user_contact_methods
SET dest = replacement_dest
WHERE id = contact_method_id
  AND dest = expected_dest;
```

Using a dedicated connection prevents `database/sql.DB` from transparently
replaying this statement after `driver.ErrBadConn`. No read, explicit lock,
advisory lock, retry, replay, regeneration, compensation, or second update is
performed.

Expected and replacement values are complete existing `DestV1` webhook
destinations containing only `webhook_url`; only the token bytes differ. The
existing compatibility trigger derives the legacy `type` and `value` columns
when `dest` changes. The operation does not modify the Contact Method ID, name,
owner, disabled state, pending state, status-update setting, metadata, or last
test-verification time.

## Result and failure model

- Exactly one affected row is confirmed success. Success returns no URL or
  token.
- Zero affected rows is a fixed conflict. Missing ID, changed expected value,
  non-Gateway current value, and a concurrent winner remain indistinguishable.
- More than one affected row is a fixed server-side integrity/unavailable
  failure.
- Either existing destination uniqueness constraint rejecting the replacement
  is a fixed conflict.
- Cancellation or deadline already present before the statement is a fixed
  canceled or deadline-exceeded result.
- A structured server rejection or a driver guarantee that the statement was
  not sent is fixed unavailable.
- The adapter preserves the boundary between statement execution and result
  inspection. Once execution may have started, an unclassified execution
  error, connection interruption, missing result, completion-unknown result,
  or any `RowsAffected` failure is fixed outcome unknown. The uncertain
  connection is discarded.

All classifications are fixed, content-free sentinels and discard the original
driver error chain. An outcome-unknown operation is never retried or reported
as success or conflict. A later coordinator must perform an authoritative
read before deciding what happened.

## Delivery overlap and deferred work

After a confirmed CAS, newly loaded deliveries use the replacement token.
Already-running sends may still hold the prior destination in memory. Safe
rotation therefore relies on Gateway's accepted bounded old/new overlap and
must not finalize the old token until the future coordinator proves the
required drain condition or deadline.

This checkpoint does not implement that coordinator, PostgreSQL integration
against an external database, HTTP or GraphQL transport, UI controls, runtime
wiring, scheduler or cleanup work, Gateway changes, provider delivery,
production secret sources, schema changes, or migrations.
