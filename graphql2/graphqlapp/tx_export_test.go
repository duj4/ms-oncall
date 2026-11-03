package graphqlapp

// Test-build-only access for external PostgreSQL compatibility tests. These
// symbols do not exist in the production binary or its transaction API.
var WithContextTxForTest = withContextTx
var HasInheritedContextTxForTest = hasInheritedContextTx
