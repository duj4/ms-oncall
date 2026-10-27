package executioncontext

import (
	"context"
	"database/sql"

	"github.com/target/goalert/gadb"
	"github.com/target/goalert/permission"
)

// WithCMNRTransaction keeps final authorization and a CM/NR write on one
// connection. Caller-owned transactions are never completed here. Unsupported
// DBTX adapters fail closed instead of falling back to unprotected statements.
// This helper is scoped to the three CMNR Store operations, not GraphQL roots.
func WithCMNRTransaction(ctx context.Context, db gadb.DBTX, operation func(*sql.Tx) error) error {
	if tx, ok := db.(*sql.Tx); ok {
		if tx == nil {
			return permission.NewAccessDenied("")
		}
		return operation(tx)
	}
	var tx *sql.Tx
	var err error
	switch db := db.(type) {
	case *sql.DB:
		if db == nil {
			return permission.NewAccessDenied("")
		}
		tx, err = db.BeginTx(ctx, nil)
	case *sql.Conn:
		if db == nil {
			return permission.NewAccessDenied("")
		}
		tx, err = db.BeginTx(ctx, nil)
	default:
		return permission.NewAccessDenied("")
	}
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := operation(tx); err != nil {
		return err
	}
	return tx.Commit()
}
