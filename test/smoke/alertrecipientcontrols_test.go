package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/alert"
	"github.com/target/goalert/lock"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func recipientExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	_, err := db.Exec(query, args...)
	require.NoError(t, err)
}
func recipientAssign(t *testing.T, h *harness.Harness, db *sql.DB, foreign bool) {
	t.Helper()
	org := h.UUID("org-b")
	if !foreign {
		require.NoError(t, db.QueryRow(`SELECT organization_id FROM services WHERE id=$1`, h.UUID("svc-a")).Scan(&org))
	}
	recipientExec(t, db, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count)
 VALUES($1,$2,'NORMAL',$2,'ORG_MEMBER','EXACTLY_ONE',now(),'outbound-isolation-control',1)
 ON CONFLICT(user_id) DO UPDATE SET effective_organization_id=$2,effective_normal_organization_id=$2,effective_organization_classification='NORMAL',organization_role='ORG_MEMBER',mapping_outcome='EXACTLY_ONE',matched_count=1`, h.UUID("target"), org)
}
func recipientAlert(t *testing.T, h *harness.Harness, db *sql.DB, service string) int {
	t.Helper()
	var id int
	require.NoError(t, db.QueryRow(`INSERT INTO alerts(service_id,summary,details,dedup_key) VALUES($1,'Outbound isolation control','Synthetic control details','auto:1:'||gen_random_uuid()::text) RETURNING id`, h.UUID(service)).Scan(&id))
	return id
}
func recipientQueue(t *testing.T, h *harness.Harness, db *sql.DB, id int, service string) string {
	t.Helper()
	msg := uuid.NewString()
	recipientExec(t, db, `INSERT INTO outgoing_messages(id,message_type,contact_method_id,user_id,alert_id,service_id,escalation_policy_id)
 VALUES($1,'alert_notification',$2,$3,$4,$5,$6)`, msg, h.UUID("cm-target"), h.UUID("target"), id, h.UUID(service), h.UUID("ep-a"))
	return msg
}
func recipientWait(t *testing.T, db *sql.DB, id, status, reason string) {
	t.Helper()
	require.Eventually(t, func() bool {
		var ok bool
		err := db.QueryRow(`SELECT last_status=$2 AND ($3='' OR status_details=$3)
 AND CASE WHEN $2='failed' THEN sent_at IS NULL AND provider_msg_id IS NULL AND cycle_id IS NULL AND next_retry_at IS NULL ELSE sent_at IS NOT NULL END FROM outgoing_messages WHERE id=$1`, id, status, reason).Scan(&ok)
		return err == nil && ok
	}, 15*time.Second, 25*time.Millisecond)
}
func recipientNoUnread(t *testing.T, h *harness.Harness) {
	t.Helper()
	raw, err := h.D08T1Sink()
	require.NoError(t, err)
	var list struct{ Messages []struct{ Read bool } }
	require.NoError(t, json.Unmarshal(raw, &list))
	for _, m := range list.Messages {
		require.True(t, m.Read, "unexpected provider delivery")
	}
}
func recipientConsume(t *testing.T, h *harness.Harness, word string) {
	t.Helper()
	require.NoError(t, h.D08T1Consume(h.Email("target"), word, ""))
}

func TestOutboundRecipientInvalidAuthorityAndRoots(t *testing.T) {
	h, db := t1New(t, false, true)
	recipientExec(t, db, `DELETE FROM user_notification_rules`)
	for _, scenario := range []string{"absent", "default", "unknown-role", "foreign-admin", "owner-mismatch", "service-mismatch", "queued-change", "duplicate-foreign"} {
		t.Run(scenario, func(t *testing.T) {
			recipientAssign(t, h, db, false)
			recipientExec(t, db, `UPDATE users SET role='user' WHERE id=$1`, h.UUID("target"))
			// The existing sender advisory lock prevents a send between the committed
			// queue insertion and committed assignment change. No provider runs under it.
			conn, err := db.Conn(t.Context())
			require.NoError(t, err)
			_, err = conn.ExecContext(t.Context(), `SELECT pg_advisory_lock($1)`, lock.GlobalMessageSending)
			require.NoError(t, err)
			defer conn.Close()
			id := recipientAlert(t, h, db, "svc-a")
			msg := recipientQueue(t, h, db, id, "svc-a")
			reason := "notification_recipient_org_denied"
			switch scenario {
			case "absent":
				recipientExec(t, db, `DELETE FROM user_organization_assignments WHERE user_id=$1`, h.UUID("target"))
			case "default":
				recipientExec(t, db, `UPDATE user_organization_assignments SET effective_organization_id=$1,effective_normal_organization_id=NULL,effective_organization_classification='DEFAULT',organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$2`, organization.DefaultOrganizationID, h.UUID("target"))
			case "unknown-role":
				recipientExec(t, db, `UPDATE users SET role='unknown' WHERE id=$1`, h.UUID("target"))
			case "foreign-admin":
				recipientAssign(t, h, db, true)
				recipientExec(t, db, `UPDATE users SET role='admin' WHERE id=$1`, h.UUID("target"))
			case "owner-mismatch":
				reason = "notification_recipient_invalid"
				recipientExec(t, db, `UPDATE outgoing_messages SET user_id=$1 WHERE id=$2`, h.UUID("control"), msg)
			case "service-mismatch":
				reason = "notification_recipient_invalid"
				recipientExec(t, db, `UPDATE outgoing_messages SET service_id=$1 WHERE id=$2`, h.UUID("svc-b"), msg)
			case "queued-change":
				recipientAssign(t, h, db, true)
			case "duplicate-foreign":
				recipientAssign(t, h, db, true)
				recipientQueue(t, h, db, id, "svc-a")
			}
			_, err = conn.ExecContext(t.Context(), `SELECT pg_advisory_unlock($1)`, lock.GlobalMessageSending)
			require.NoError(t, err)
			h.Trigger()
			recipientWait(t, db, msg, "failed", reason)
			recipientNoUnread(t, h)
			h.FastForward(time.Minute)
			h.Trigger()
			recipientWait(t, db, msg, "failed", reason)
			var retries int
			require.NoError(t, db.QueryRow(`SELECT retry_count FROM outgoing_messages WHERE id=$1`, msg).Scan(&retries))
			require.Zero(t, retries)
			t1Snapshot(t, db, "final")
			t1Sink(t, h, "sink-final")
		})
	}
}

func TestOutboundRecipientStatusAndLifecycle(t *testing.T) {
	h, db := t1New(t, false, true)
	recipientExec(t, db, `UPDATE user_contact_methods SET enable_status_updates=true`)
	id := t1Alert(t, h, db, "D08 status lifecycle")
	t1Receive(t, h, "target", "D08 status lifecycle")
	t1Receive(t, h, "control", "D08 status lifecycle")
	ctx := permission.SystemContext(context.Background(), "OutboundIsolationControl")
	require.NoError(t, h.App().AlertStore.UpdateStatus(ctx, id, alert.StatusActive))
	h.Trigger()
	h.FastForward(4 * time.Minute)
	h.Trigger()
	require.NoError(t, h.D08T1Consume(h.Email("target"), "Acknowledged", ""))
	require.NoError(t, h.D08T1Consume(h.Email("control"), "Acknowledged", ""))
	recipientAssign(t, h, db, true)
	require.NoError(t, h.App().AlertStore.UpdateStatus(ctx, id, alert.StatusClosed))
	h.Trigger()
	h.FastForward(4 * time.Minute)
	h.Trigger()
	require.NoError(t, h.D08T1Consume(h.Email("control"), "Closed", ""))
	var msg string
	require.Eventually(t, func() bool {
		return db.QueryRow(`SELECT id FROM outgoing_messages WHERE alert_id=$1 AND contact_method_id=$2 AND message_type='alert_status_update' AND last_status='failed'`, id, h.UUID("cm-target")).Scan(&msg) == nil
	}, 15*time.Second, 25*time.Millisecond)
	recipientWait(t, db, msg, "failed", "notification_recipient_org_denied")
	recipientNoUnread(t, h)
	var state string
	require.NoError(t, db.QueryRow(`SELECT status FROM alerts WHERE id=$1`, id).Scan(&state))
	require.Equal(t, "closed", state)
	t1Snapshot(t, db, "final")
	t1Sink(t, h, "sink-final")
}

func TestOutboundRecipientBundleSources(t *testing.T) {
	h, db := t1New(t, false, true)
	recipientExec(t, db, `DELETE FROM user_notification_rules`)
	for _, scenario := range []string{"valid", "foreign", "mixed-source", "missing-source", "nested"} {
		t.Run(scenario, func(t *testing.T) {
			h.FastForward(2 * time.Minute)
			recipientAssign(t, h, db, scenario == "foreign")
			conn, err := db.Conn(t.Context())
			require.NoError(t, err)
			defer conn.Close()
			_, err = conn.ExecContext(t.Context(), `SELECT pg_advisory_lock($1)`, lock.GlobalMessageSending)
			require.NoError(t, err)
			bundle := uuid.NewString()
			recipientExec(t, db, `INSERT INTO outgoing_messages(id,message_type,contact_method_id,user_id,service_id) VALUES($1,'alert_notification_bundle',$2,$3,$4)`, bundle, h.UUID("cm-target"), h.UUID("target"), h.UUID("svc-a"))
			if scenario != "missing-source" {
				parent := bundle
				if scenario == "nested" {
					parent = uuid.NewString()
					recipientExec(t, db, `INSERT INTO outgoing_messages(id,message_type,contact_method_id,user_id,service_id,last_status,status_details) VALUES($1,'alert_notification_bundle',$2,$3,$4,'bundled',$5)`, parent, h.UUID("cm-target"), h.UUID("target"), h.UUID("svc-a"), bundle)
				}
				for i := 0; i < 2; i++ {
					service := "svc-a"
					if scenario == "mixed-source" && i == 1 {
						service = "svc-b"
					}
					alertID := recipientAlert(t, h, db, service)
					child := recipientQueue(t, h, db, alertID, "svc-a")
					recipientExec(t, db, `UPDATE outgoing_messages SET last_status='bundled',status_details=$1 WHERE id=$2`, parent, child)
				}
			}
			_, err = conn.ExecContext(t.Context(), `SELECT pg_advisory_unlock($1)`, lock.GlobalMessageSending)
			require.NoError(t, err)
			h.Trigger()
			switch scenario {
			case "valid", "nested":
				recipientWait(t, db, bundle, "sent", "")
				recipientConsume(t, h, "unacknowledged alerts")
			case "foreign":
				recipientWait(t, db, bundle, "failed", "notification_recipient_org_denied")
			default:
				recipientWait(t, db, bundle, "failed", "notification_recipient_invalid")
			}
			recipientNoUnread(t, h)
			t1Snapshot(t, db, "final")
			t1Sink(t, h, "sink-final")
		})
	}
}

func TestOutboundRecipientDatabaseTimeoutRetry(t *testing.T) {
	h, db := t1New(t, false, true)
	recipientExec(t, db, `DELETE FROM user_notification_rules`)
	// Block only the assignment read in the actual guard. PostgreSQL and the
	// durable outbox remain available so the real message manager records retry.
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`LOCK user_organization_assignments IN ACCESS EXCLUSIVE MODE`)
	require.NoError(t, err)
	expect := h.ExpectBackendError("notification_authority_unavailable")
	expectSlow := h.ExpectBackendError("slow cycle finished")
	id := recipientAlert(t, h, db, "svc-a")
	msg := recipientQueue(t, h, db, id, "svc-a")
	h.Trigger()
	require.Eventually(t, func() bool {
		var ok bool
		err := db.QueryRow(`SELECT last_status='failed' AND status_details='notification_authority_unavailable' AND next_retry_at IS NOT NULL AND sent_at IS NULL AND provider_msg_id IS NULL FROM outgoing_messages WHERE id=$1`, msg).Scan(&ok)
		return err == nil && ok
	}, 12*time.Second, 25*time.Millisecond)
	expect()
	expectSlow()
	recipientNoUnread(t, h)
	var failed string
	require.NoError(t, db.QueryRow(`SELECT to_jsonb(m)::text FROM outgoing_messages m WHERE id=$1`, msg).Scan(&failed))
	t1Write(t, "temporary-failure", json.RawMessage(failed))
	require.NoError(t, tx.Commit())
	h.FastForward(time.Minute)
	h.Trigger()
	recipientWait(t, db, msg, "sent", "")
	recipientConsume(t, h, "Outbound isolation control")
	var retries int
	require.NoError(t, db.QueryRow(`SELECT retry_count FROM outgoing_messages WHERE id=$1`, msg).Scan(&retries))
	require.Equal(t, 1, retries)
	// A second pending retry must independently recheck a newly foreign user.
	recipientExec(t, db, `UPDATE outgoing_messages SET last_status='failed',next_retry_at=now()-interval '1 second',sent_at=NULL,provider_msg_id=NULL WHERE id=$1`, msg)
	recipientAssign(t, h, db, true)
	h.FastForward(2 * time.Minute)
	h.Trigger()
	recipientWait(t, db, msg, "failed", "notification_recipient_org_denied")
	recipientNoUnread(t, h)
	t1Snapshot(t, db, "retry-rejected")
	t1Sink(t, h, "sink-final")
}

func TestOutboundRecipientUnrelatedDeliveries(t *testing.T) {
	h, db := t1New(t, true, true)
	recipientExec(t, db, `DELETE FROM user_notification_rules`)
	ctx := permission.UserContext(context.Background(), h.UUID("target"), permission.RoleUser)
	require.NoError(t, h.App().NotificationStore.SendContactMethodTest(ctx, h.UUID("cm-target")))
	h.Trigger()
	recipientConsume(t, h, "Test Message")
	h.FastForward(5 * time.Minute)
	require.NoError(t, h.App().NotificationStore.SendContactMethodVerification(ctx, h.UUID("cm-target")))
	h.Trigger()
	recipientConsume(t, h, "Verification Message")
	h.FastForward(2 * time.Minute)
	// A channel has no user recipient; its existing delivery contract is retained.
	channel := uuid.NewString()
	recipientExec(t, db, `INSERT INTO notification_channels(id,name,dest) SELECT $1,'Synthetic channel',dest FROM user_contact_methods WHERE id=$2`, channel, h.UUID("cm-target"))
	id := recipientAlert(t, h, db, "svc-a")
	msg := uuid.NewString()
	recipientExec(t, db, `INSERT INTO outgoing_messages(id,message_type,channel_id,alert_id,service_id,escalation_policy_id) VALUES($1,'alert_notification',$2,$3,$4,$5)`, msg, channel, id, h.UUID("svc-a"), h.UUID("ep-a"))
	h.Trigger()
	recipientWait(t, db, msg, "sent", "")
	recipientConsume(t, h, "Outbound isolation control")
	recipientNoUnread(t, h)
	t1Snapshot(t, db, "final")
	t1Sink(t, h, "sink-final")
}

func TestOutboundRecipientAutomaticBundle(t *testing.T) {
	h, db := t1New(t, true, true)
	h.SetConfigValue("General.DisableMessageBundles", "false")
	conn, err := db.Conn(t.Context())
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.ExecContext(t.Context(), `SELECT pg_advisory_lock($1)`, lock.GlobalMessageSending)
	require.NoError(t, err)
	for range 3 {
		recipientAlert(t, h, db, "svc-a")
	}
	h.Trigger()
	_, err = conn.ExecContext(t.Context(), `SELECT pg_advisory_unlock($1)`, lock.GlobalMessageSending)
	require.NoError(t, err)
	h.Trigger()
	var foreign, control string
	require.Eventually(t, func() bool {
		err := db.QueryRow(`SELECT id FROM outgoing_messages WHERE message_type='alert_notification_bundle' AND contact_method_id=$1 AND last_status='failed'`, h.UUID("cm-target")).Scan(&foreign)
		return err == nil
	}, 15*time.Second, 25*time.Millisecond)
	recipientWait(t, db, foreign, "failed", "notification_recipient_org_denied")
	require.Eventually(t, func() bool {
		return db.QueryRow(`SELECT id FROM outgoing_messages WHERE message_type='alert_notification_bundle' AND contact_method_id=$1 AND last_status='sent'`, h.UUID("cm-control")).Scan(&control) == nil
	}, 15*time.Second, 25*time.Millisecond)
	recipientWait(t, db, control, "sent", "")
	require.NoError(t, h.D08T1Consume(h.Email("control"), "unacknowledged alerts", ""))
	recipientNoUnread(t, h)
	t1Snapshot(t, db, "final")
	t1Sink(t, h, "sink-final")
}
