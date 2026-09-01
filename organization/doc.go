// Package organization provides the internal persistence foundation for
// Organization identity. It deliberately has no GraphQL, HTTP, authorization,
// User-assignment, or operational-resource integration.
//
// Normal Organizations are created as a base Organization and constrained
// relational subtype in one transaction. The distinguished Default
// Organization is migration-owned and can only be read through this package.
// No hard-delete or generic classification-based create operation is exposed.
package organization
