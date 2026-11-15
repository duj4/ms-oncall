// Package deletionsafety models the frozen SPEC1 V1 deletion policy. It contains
// no collectors, authorization checks, database access, transactions, or delete
// operations. Its callers must supply complete, authorized, safe projections
// from a consistent snapshot and revalidate inside the owning transaction.
//
// Resource IDs must be non-secret business identities. In particular, an
// integration key uses audit_resource_id, never its credential selector. JSON
// fragments need envelope-scoped identities, including their fragment ordinal;
// a count or a user ID alone is not a fragment identity. Parent and Owner are
// independently collected identities, not authority supplied by a client.
//
// The impact version binds safety semantics, not authorization. It cannot grant
// permission, prove that a preview was issued, or replace transaction fencing.
package deletionsafety
