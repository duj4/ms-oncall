package graphqlapp

import (
	context "context"
	"database/sql"

	"github.com/target/goalert/util/errutil"
	"github.com/target/goalert/util/sqlutil"
)

// Only this package's helper installs this key. Client fields, headers and
// ordinary string context keys cannot claim ownership of an inherited Tx.
type contextTxKey int

const txKey = contextTxKey(0)

func hasInheritedContextTx(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	_, ok := ctx.Value(txKey).(*sql.Tx)
	return ok
}

// withContextTx is a helper function that handles starting and using a single transaction for a request.
//
// If there is not already a nested transaction in the current context, one is started and a new
// context is passed to fn.
// The transaction is then given to the provided fn.
//
// Commit and Rollback are handled automatically.
// Any nested calls to `withContextTx` will inherit the original transaction from the new context.
func withContextTx(ctx context.Context, db *sql.DB, fn func(context.Context, *sql.Tx) error) error {
	run := func() error {
		if tx, ok := ctx.Value(txKey).(*sql.Tx); ok {
			// Transaction already exists, run fn with
			// the original context, and pass in the open
			// Tx.
			return fn(ctx, tx)
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer sqlutil.Rollback(ctx, "graphql: context tx", tx)

		err = fn(context.WithValue(ctx, txKey, tx), tx)
		if err != nil {
			return err
		}

		return tx.Commit()
	}

	// Ensure returned DB errors are mapped.
	return errutil.MapDBError(run())
}
