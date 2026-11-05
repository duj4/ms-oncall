package engine

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/target/goalert/engine/message"
	"github.com/target/goalert/notification"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/retry"
	"github.com/target/goalert/util/log"
)

// The existing bundler/deduplicator records child -> parent in status_details.
// Walk those persisted links, including nested bundles and duplicate alerts.
// UNION terminates even a malformed cycle. Every bundle must have children and
// every alert must independently resolve to the same actual Service. A legacy
// bundle whose source evidence has disappeared is deliberately rejected.
const alertRecipientQuery = `
WITH RECURSIVE related AS (
    SELECT m.id, m.message_type, m.contact_method_id, m.channel_id, m.user_id,
        m.service_id, m.alert_id, m.alert_log_id, m.last_status, m.status_details
    FROM outgoing_messages m WHERE m.id = $1
    UNION
    SELECT c.id, c.message_type, c.contact_method_id, c.channel_id, c.user_id,
        c.service_id, c.alert_id, c.alert_log_id, c.last_status, c.status_details
    FROM outgoing_messages c
    JOIN related p ON c.last_status = 'bundled' AND c.status_details = p.id::text
)
SELECT cm.user_id, s.organization_id, coalesce(
    m.last_status = 'sending'
    AND m.message_type = $2
    AND m.contact_method_id = $3
    AND m.channel_id IS NULL
    AND cm.user_id = $4
    AND cm.dest = $5::jsonb
    AND NOT cm.disabled
    AND m.service_id IS NOT DISTINCT FROM nullif($6, '')::uuid
    AND coalesce(m.alert_id, 0) = $7
    AND coalesce(m.alert_log_id, 0) = $8
    AND (SELECT bool_and(coalesce(
        r.contact_method_id = cm.id
        AND r.channel_id IS NULL
        AND r.user_id = cm.user_id
        AND (r.service_id = s.id OR r.message_type = 'alert_status_update' AND r.service_id IS NULL)
        AND CASE r.message_type
            WHEN 'alert_notification' THEN
                a.id IS NOT NULL AND a.service_id = s.id AND r.alert_log_id IS NULL
            WHEN 'alert_status_update' THEN
                r.id = m.id AND a.id IS NOT NULL AND a.service_id = s.id
                AND l.alert_id = a.id
            WHEN 'alert_notification_bundle' THEN
                r.alert_id IS NULL AND r.alert_log_id IS NULL
                AND EXISTS (SELECT 1 FROM related c
                    WHERE c.last_status = 'bundled' AND c.status_details = r.id::text)
            ELSE false
        END, false))
        FROM related r
        LEFT JOIN alerts a ON a.id = r.alert_id
        LEFT JOIN alert_logs l ON l.id = r.alert_log_id)
    AND (m.message_type <> 'alert_notification_bundle'
        OR EXISTS (SELECT 1 FROM related WHERE message_type = 'alert_notification')),
    false)
FROM outgoing_messages m
JOIN user_contact_methods cm ON cm.id = m.contact_method_id
LEFT JOIN alerts root_alert ON root_alert.id = m.alert_id
JOIN services s ON s.id = coalesce(m.service_id, root_alert.service_id)
WHERE m.id = $1
`

// Keep the underlying database error out of formatting/logging while retaining
// cancellation and the existing temporary-error classification for retries.
type recipientAuthorityError struct{ cause error }

func (recipientAuthorityError) Error() string { return "notification_authority_unavailable" }
func (recipientAuthorityError) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprint(state, "notification_authority_unavailable")
}
func (e recipientAuthorityError) Is(target error) bool { return errors.Is(e.cause, target) }
func (e recipientAuthorityError) Temporary() bool      { return retry.IsTemporaryError(e.cause) }

func (p *Engine) guardAlertRecipient(ctx context.Context, msg *message.Message) (*notification.SendResult, error) {
	if !msg.DestID.IsUserCM() {
		return nil, nil
	}
	switch msg.Type {
	case notification.MessageTypeAlert, notification.MessageTypeAlertStatus, notification.MessageTypeAlertBundle:
	default:
		return nil, nil
	}

	reject := func(reason string) (*notification.SendResult, error) {
		log.Logf(log.WithField(ctx, "Reason", reason), "notification recipient rejected")
		return &notification.SendResult{ID: msg.ID, Status: notification.Status{
			State: notification.StateFailedPerm, Details: reason,
		}}, nil
	}
	ids := []string{msg.ID, msg.UserID}
	if msg.Type != notification.MessageTypeAlertStatus || msg.ServiceID != "" {
		ids = append(ids, msg.ServiceID)
	}
	for _, id := range ids {
		value, err := uuid.Parse(id)
		if err != nil || value == uuid.Nil {
			return reject("notification_recipient_invalid")
		}
	}

	// Each actual send attempt observes fresh committed authority in a consistent
	// snapshot. Release the read-only transaction before any provider network IO.
	// This is not a fence against concurrent external assignment SQL after it.
	tx, err := p.b.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, recipientAuthorityError{cause: err}
	}
	defer func() { _ = tx.Rollback() }()

	var ownerID, orgID uuid.UUID
	var valid bool
	err = tx.QueryRowContext(ctx, alertRecipientQuery, msg.ID, msg.Type, msg.DestID.CMID,
		msg.UserID, msg.Dest, msg.ServiceID, msg.AlertID, msg.AlertLogID).Scan(&ownerID, &orgID, &valid)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !valid {
		return reject("notification_recipient_invalid")
	}
	if err != nil {
		return nil, recipientAuthorityError{cause: err}
	}
	err = organization.NewStore(p.b.db).ValidateUserOrganizationTx(ctx, tx, ownerID, orgID)
	if errors.Is(err, organization.ErrNotFound) {
		return reject("notification_recipient_org_denied")
	}
	if err != nil {
		return nil, recipientAuthorityError{cause: err}
	}
	if err = tx.Commit(); err != nil {
		return nil, recipientAuthorityError{cause: err}
	}
	return nil, nil
}
