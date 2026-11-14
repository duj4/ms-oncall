package auth

import (
	"context"
	"database/sql"

	"github.com/target/goalert/auth/sessionaudit"
)

// These methods require the controller's transaction and never commit. Existing
// Logout, expiration and cleanup retain their separate, unchanged behavior.
func (h *Handler) EndUserSessionsForAuditTx(ctx context.Context, tx *sql.Tx, e sessionaudit.Event, ids ...string) (*sessionaudit.Receipt, error) {
	return sessionaudit.RevokeSelected(ctx, tx, e, ids...)
}
func (h *Handler) EndOtherUserSessionsForAuditTx(ctx context.Context, tx *sql.Tx, e sessionaudit.Event) (*sessionaudit.Receipt, error) {
	return sessionaudit.RevokeOtherSelf(ctx, tx, e)
}
