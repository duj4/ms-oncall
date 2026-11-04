package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/app"
	"github.com/target/goalert/test/smoke/harness"
)

const t1Common = `
INSERT INTO organizations(id,classification,display_name,canonical_name)
VALUES ({{uuid "org-b"}},'NORMAL','D08 T1 Org B','d08-t1-b');
INSERT INTO normal_organizations(organization_id,organization_classification,corporate_mapping_key,iana_time_zone)
VALUES ({{uuid "org-b"}},'NORMAL','synthetic:d08-t1-b','Asia/Shanghai');
INSERT INTO users(id,name,email,role) VALUES
 ({{uuid "target"}},'Synthetic target','target@example.invalid','user'),
 ({{uuid "control"}},'Synthetic home control','control@example.invalid','user');
INSERT INTO user_contact_methods(id,user_id,name,type,value) VALUES
 ({{uuid "cm-target"}},{{uuid "target"}},'synthetic immediate','EMAIL',{{email "target"}}),
 ({{uuid "cm-delayed"}},{{uuid "target"}},'synthetic delayed','EMAIL',{{email "delayed"}}),
 ({{uuid "cm-control"}},{{uuid "control"}},'synthetic home','EMAIL',{{email "control"}});
INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES
 ({{uuid "target"}},{{uuid "cm-target"}},0),
 ({{uuid "control"}},{{uuid "cm-control"}},0);
INSERT INTO escalation_policies(id,name,organization_id) VALUES
 ({{uuid "ep-a"}},'D08 T1 Home Policy',{{smokeOrganizationID}}),
 ({{uuid "ep-b"}},'D08 T1 Unrelated Policy',{{uuid "org-b"}});
INSERT INTO escalation_policy_steps(id,escalation_policy_id,delay)
VALUES ({{uuid "step-a"}},{{uuid "ep-a"}},60);
INSERT INTO services(id,name,escalation_policy_id,organization_id) VALUES
 ({{uuid "svc-a"}},'D08 T1 Home Service',{{uuid "ep-a"}},{{smokeOrganizationID}}),
 ({{uuid "svc-b"}},'D08 T1 Unrelated Service',{{uuid "ep-b"}},{{uuid "org-b"}});
`
const t1Rotation = `
INSERT INTO rotations(id,name,type,start_time,shift_length,time_zone,organization_id)
VALUES ({{uuid "rot-a"}},'D08 T1 Home Rotation','daily',now(),1,'Asia/Shanghai',{{smokeOrganizationID}});
INSERT INTO rotation_participants(id,rotation_id,user_id,position)
VALUES ({{uuid "part-target"}},{{uuid "rot-a"}},{{uuid "target"}},0);
INSERT INTO schedules(id,name,time_zone,organization_id)
VALUES ({{uuid "sched-a"}},'D08 T1 Home Schedule','Asia/Shanghai',{{smokeOrganizationID}});
INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id)
VALUES ({{uuid "rule-rot"}},{{uuid "sched-a"}},{{uuid "rot-a"}});
INSERT INTO schedule_rules(id,schedule_id,tgt_user_id)
VALUES ({{uuid "rule-control"}},{{uuid "sched-a"}},{{uuid "control"}});
INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,schedule_id)
VALUES ({{uuid "action-sched"}},{{uuid "step-a"}},{{uuid "sched-a"}});
`
const t1Direct = `
INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES
 ({{uuid "action-target"}},{{uuid "step-a"}},{{uuid "target"}}),
 ({{uuid "action-control"}},{{uuid "step-a"}},{{uuid "control"}});
`

func t1Write(t *testing.T, name string, value any) {
	if os.Getenv("D08_T1_EVIDENCE") == "" {
		return
	}
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	require.NoError(t, err)
	dir := filepath.Join(os.Getenv("D08_T1_EVIDENCE"), t.Name())
	require.NoError(t, os.MkdirAll(dir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, name+".json"), append(data, '\n'), 0600))
}
func t1Snapshot(t *testing.T, db *sql.DB, label string) map[string]json.RawMessage {
	t.Helper()
	tables := []string{"organizations", "normal_organizations", "users", "user_organization_assignments", "rotations", "rotation_participants", "rotation_state", "schedules", "schedule_rules", "schedule_data", "user_overrides", "schedule_on_call_users", "escalation_policies", "escalation_policy_steps", "escalation_policy_actions", "ep_step_on_call_users", "services", "alerts", "escalation_policy_state", "notification_policy_cycles", "user_notification_rules", "user_contact_methods", "outgoing_messages", "alert_logs"}
	state := map[string]json.RawMessage{}
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	for _, table := range tables {
		var raw string
		require.NoError(t, tx.QueryRow("SELECT coalesce(jsonb_agg(x ORDER BY x::text),'[]'::jsonb)::text FROM (SELECT to_jsonb(t) AS x FROM "+table+" t) a").Scan(&raw), table)
		state[table] = json.RawMessage(raw)
	}
	require.NoError(t, tx.Commit())
	t1Write(t, label, state)
	return state
}
func t1New(t *testing.T, foreign, direct bool) (*harness.Harness, *sql.DB) {
	t.Helper()
	org := "{{smokeOrganizationID}}"
	if foreign {
		org = `{{uuid "org-b"}}`
	}
	fixture := t1Common + fmt.Sprintf(`
INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count)
VALUES ({{uuid "target"}},%s,'NORMAL',%s,'ORG_MEMBER','EXACTLY_ONE',now(),'d08-t1-r0-synthetic',1);
`, org, org)
	if direct {
		fixture += t1Direct
	} else {
		fixture += t1Rotation
	}
	if t.Name() == "TestOutboundRecipientAssignmentChange" {
		fixture += `INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES ({{uuid "target"}},{{uuid "cm-delayed"}},2);`
	}
	t1Write(t, "fixture-template", fixture)
	h := harness.NewStoppedHarness(t, fixture, nil, "")
	db, err := h.OutboundIsolationDB()
	require.NoError(t, err)
	query := "INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES($1,$2,$3,1)"
	parent := h.UUID("rot-a")
	if direct {
		query = "INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)"
		parent = h.UUID("step-a")
	}
	_, invalidErr := db.Exec(query, h.UUID("invalid-rel"), parent, h.UUID("missing-user"))
	var fk *pgconn.PgError
	require.ErrorAs(t, invalidErr, &fk)
	require.Equal(t, "23503", fk.Code)
	t1Write(t, "negative-missing-user", map[string]any{"sql": query, "sqlstate": fk.Code, "constraint": fk.ConstraintName, "invalid_relationship_rejected": true})
	t1Write(t, "database", map[string]any{"task_owned": true, "current_public_transfer_api": false, "data_origin": "synthetic fixture in new task-owned cluster"})
	t1Snapshot(t, db, "00-before-engine")
	var schema string
	require.NoError(t, db.QueryRow(`SELECT jsonb_build_object(
 'constraints',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',conrelid::regclass::text,'name',conname,'definition',pg_get_constraintdef(oid)) ORDER BY conrelid,conname),'[]') FROM pg_constraint WHERE conrelid IN ('rotation_participants'::regclass,'rotation_state'::regclass,'schedule_rules'::regclass,'user_overrides'::regclass,'schedule_on_call_users'::regclass,'escalation_policy_actions'::regclass,'ep_step_on_call_users'::regclass,'notification_policy_cycles'::regclass,'user_organization_assignments'::regclass,'outgoing_messages'::regclass)),
 'triggers',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',tgrelid::regclass::text,'name',tgname,'definition',pg_get_triggerdef(oid),'function',pg_get_functiondef(tgfoid)) ORDER BY tgrelid,tgname),'[]') FROM pg_trigger WHERE NOT tgisinternal AND tgrelid IN ('rotation_participants'::regclass,'schedule_rules'::regclass,'user_overrides'::regclass,'schedule_on_call_users'::regclass,'escalation_policy_actions'::regclass,'notification_policy_cycles'::regclass,'user_organization_assignments'::regclass)),
 'assignment_columns',(SELECT jsonb_agg(column_name ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name='user_organization_assignments'),
 'version',version())::text`).Scan(&schema))
	t1Write(t, "schema", json.RawMessage(schema))
	logRoot := os.Getenv("D08_T1_EVIDENCE")
	if logRoot == "" {
		logRoot = t.TempDir()
	}
	require.NoError(t, os.MkdirAll(filepath.Join(logRoot, t.Name()), 0700))
	logfile, err := os.OpenFile(filepath.Join(logRoot, t.Name(), "engine.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require.NoError(t, err)
	t.Cleanup(func() { logfile.Close() })
	h.StartWithAppCfgHook(func(c *app.Config) {
		c.InitialConfig.Slack.Enable = false
		c.InitialConfig.Twilio.Enable = false
		c.InitialConfig.Mailgun.Enable = false
		c.InitialConfig.Webhook.Enable = false
		c.LegacyLogger.SetOutput(io.MultiWriter(c.LegacyLogger.Logrus().Out, logfile))
	})
	t.Cleanup(h.Close)
	t.Cleanup(func() { db.Close() })
	return h, db
}
func t1Receive(t *testing.T, h *harness.Harness, address, summary string) {
	t.Helper()
	require.NoError(t, h.D08T1Consume(h.Email(address), summary, "D08-T1 SYNTHETIC HOME ALERT DETAILS"))
}
func t1Sink(t *testing.T, h *harness.Harness, label string) {
	t.Helper()
	raw, err := h.D08T1Sink()
	require.NoError(t, err)
	t1Write(t, label, json.RawMessage(raw))
}
func t1AssertResolved(t *testing.T, h *harness.Harness, db *sql.DB, direct bool) {
	t.Helper()
	require.Eventually(t, func() bool {
		var count int
		err := db.QueryRow("SELECT count(*) FROM ep_step_on_call_users WHERE ep_step_id=$1 AND user_id IN ($2,$3) AND end_time IS NULL", h.UUID("step-a"), h.UUID("target"), h.UUID("control")).Scan(&count)
		return err == nil && count == 2
	}, 15*time.Second, 25*time.Millisecond)
	if !direct {
		var count int
		require.NoError(t, db.QueryRow("SELECT count(*) FROM schedule_on_call_users WHERE schedule_id=$1 AND user_id IN ($2,$3) AND end_time IS NULL", h.UUID("sched-a"), h.UUID("target"), h.UUID("control")).Scan(&count))
		require.Equal(t, 2, count)
	}
}
func t1Unrelated(t *testing.T, h *harness.Harness, db *sql.DB) string {
	t.Helper()
	var raw string
	require.NoError(t, db.QueryRow(`SELECT jsonb_build_object('organization',(SELECT to_jsonb(o) FROM organizations o WHERE id=$1),'normal',(SELECT to_jsonb(n) FROM normal_organizations n WHERE organization_id=$1),'service',(SELECT to_jsonb(s) FROM services s WHERE id=$2),'policy',(SELECT to_jsonb(p) FROM escalation_policies p WHERE id=$3),'alerts',(SELECT coalesce(jsonb_agg(a),'[]') FROM alerts a WHERE service_id=$2))::text`, h.UUID("org-b"), h.UUID("svc-b"), h.UUID("ep-b")).Scan(&raw))
	return raw
}
func t1AssertForeign(t *testing.T, h *harness.Harness, db *sql.DB, foreign bool) {
	t.Helper()
	var matches bool
	require.NoError(t, db.QueryRow("SELECT a.effective_organization_id=s.organization_id FROM user_organization_assignments a CROSS JOIN services s WHERE a.user_id=$1 AND s.id=$2", h.UUID("target"), h.UUID("svc-a")).Scan(&matches))
	require.Equal(t, !foreign, matches)
}
func t1Alert(t *testing.T, h *harness.Harness, db *sql.DB, summary string) int {
	t.Helper()
	var id int
	require.NoError(t, db.QueryRow("INSERT INTO alerts(service_id,summary,details,dedup_key) VALUES($1,$2,$3,'auto:1:'||$2) RETURNING id", h.UUID("svc-a"), summary, "D08-T1 SYNTHETIC HOME ALERT DETAILS").Scan(&id))
	h.Trigger()
	return id
}
func TestOutboundRecipientHistoricalRotation(t *testing.T) {
	h, db := t1New(t, true, false)
	untouched := t1Unrelated(t, h, db)
	t1AssertForeign(t, h, db, true)
	h.Trigger()
	t1AssertResolved(t, h, db, false)
	t1Snapshot(t, db, "01-resolved-before-alert")
	id := t1Alert(t, h, db, "D08-T1-01 historical rotation")
	t1Rejected(t, h, db, id, "cm-target", 1)
	t1Receive(t, h, "control", "D08-T1-01")
	t1Sink(t, h, "sink-final")
	t1Snapshot(t, db, "02-after-notification")
	require.Equal(t, untouched, t1Unrelated(t, h, db))
	t1Write(t, "result", map[string]any{"scenario": "T1-01", "alert_id": id, "historical_foreign_rotation_resolved": true, "foreign_rejected_same_org_control_received_home_alert_details": true, "unrelated_org_unchanged": true, "classification": "ISOLATED HISTORICAL-DATA REPRODUCTION — NOT VERIFIED IN PRODUCTION"})
}
func TestOutboundRecipientAssignmentChange(t *testing.T) {
	h, db := t1New(t, false, false)
	untouched := t1Unrelated(t, h, db)
	t1AssertForeign(t, h, db, false)
	h.Trigger()
	t1AssertResolved(t, h, db, false)
	oldAlert := t1Alert(t, h, db, "D08-T1-02 before assignment change")
	t1Receive(t, h, "target", "D08-T1-02 before")
	t1Receive(t, h, "control", "D08-T1-02 before")
	before := t1Snapshot(t, db, "01-legal-cycle-before-change")
	var oldCycle string
	require.NoError(t, db.QueryRow("SELECT id FROM notification_policy_cycles WHERE alert_id=$1 AND user_id=$2", oldAlert, h.UUID("target")).Scan(&oldCycle))
	query := "UPDATE user_organization_assignments SET effective_organization_id=$1,effective_normal_organization_id=$1,authoritative_evaluated_at=statement_timestamp(),source_config_version='d08-t1-data-plane-simulation' WHERE user_id=$2"
	t1Write(t, "assignment-change-command", map[string]any{"sql": query, "org_b": h.UUID("org-b"), "user": h.UUID("target"), "label": "DATA-PLANE SIMULATION / NOT A PUBLIC TRANSFER API"})
	res, err := db.Exec(query, h.UUID("org-b"), h.UUID("target"))
	require.NoError(t, err)
	n, err := res.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	t1AssertForeign(t, h, db, true)
	immediate := t1Snapshot(t, db, "02-immediately-after-change")
	require.JSONEq(t, string(before["rotation_participants"]), string(immediate["rotation_participants"]))
	var sameCycle string
	require.NoError(t, db.QueryRow("SELECT id FROM notification_policy_cycles WHERE alert_id=$1 AND user_id=$2", oldAlert, h.UUID("target")).Scan(&sameCycle))
	require.Equal(t, oldCycle, sameCycle)
	h.FastForward(3 * time.Minute)
	h.Trigger()
	t1AssertResolved(t, h, db, false)
	t1Rejected(t, h, db, oldAlert, "cm-delayed", 1)
	t1Sink(t, h, "sink-old-cycle-after-change")
	t1Snapshot(t, db, "03-old-cycle-delayed-rejected")
	newAlert := t1Alert(t, h, db, "D08-T1-02 after assignment change")
	t1Rejected(t, h, db, newAlert, "cm-target", 1)
	t1Receive(t, h, "control", "D08-T1-02 after")
	t1Snapshot(t, db, "04-new-cycle-after-change")
	h.FastForward(3 * time.Minute)
	h.Trigger()
	t1Rejected(t, h, db, newAlert, "cm-delayed", 1)
	t1Sink(t, h, "sink-final")
	t1Snapshot(t, db, "05-final")
	require.Equal(t, untouched, t1Unrelated(t, h, db))
	t1Write(t, "result", map[string]any{"scenario": "T1-02", "label": "DATA-PLANE SIMULATION / NOT A PUBLIC TRANSFER API", "old_alert": oldAlert, "new_alert": newAlert, "old_cycle": oldCycle, "old_cycle_delayed_rejected_after_change": true, "new_cycle_foreign_immediate_and_delayed_rejected": true, "same_org_control_received_both_alerts": true, "unrelated_org_unchanged": true})
}
func TestOutboundRecipientHistoricalDirectUser(t *testing.T) {
	h, db := t1New(t, true, true)
	untouched := t1Unrelated(t, h, db)
	t1AssertForeign(t, h, db, true)
	h.Trigger()
	t1AssertResolved(t, h, db, true)
	t1Snapshot(t, db, "01-resolved-before-alert")
	id := t1Alert(t, h, db, "D08-T1-03 historical direct user")
	t1Rejected(t, h, db, id, "cm-target", 1)
	t1Receive(t, h, "control", "D08-T1-03")
	t1Sink(t, h, "sink-final")
	t1Snapshot(t, db, "02-after-notification")
	require.Equal(t, untouched, t1Unrelated(t, h, db))
	t1Write(t, "result", map[string]any{"scenario": "T1-03", "alert_id": id, "historical_foreign_direct_user_resolved": true, "foreign_rejected_same_org_control_received_home_alert_details": true, "unrelated_org_unchanged": true, "classification": "ISOLATED HISTORICAL-DATA REPRODUCTION — NOT VERIFIED IN PRODUCTION"})
}

// Assert terminal persistence before observing the sink: a timeout alone is
// not evidence of authorization enforcement. No provider ID or successful
// send timestamp may be recorded for a rejected attempt.
func t1Rejected(t *testing.T, h *harness.Harness, db *sql.DB, alertID int, cm string, count int) {
	t.Helper()
	require.Eventually(t, func() bool {
		var n int
		err := db.QueryRow(`SELECT count(*) FROM outgoing_messages WHERE alert_id=$1 AND contact_method_id=$2 AND last_status='failed' AND status_details='notification_recipient_org_denied' AND next_retry_at IS NULL AND cycle_id IS NULL AND sent_at IS NULL AND provider_msg_id IS NULL`, alertID, h.UUID(cm)).Scan(&n)
		return err == nil && n >= count
	}, 15*time.Second, 25*time.Millisecond)
	raw, err := h.D08T1Sink()
	require.NoError(t, err)
	var list struct {
		Messages []struct {
			Read bool
			To   []struct{ Address string }
		}
	}
	require.NoError(t, json.Unmarshal(raw, &list))
	address := "target"
	if cm == "cm-delayed" {
		address = "delayed"
	}
	for _, msg := range list.Messages {
		if msg.Read {
			continue
		}
		for _, to := range msg.To {
			require.NotEqual(t, h.Email(address), to.Address, "rejected recipient reached SMTP sink")
		}
	}
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM outgoing_messages WHERE alert_id=$1 AND contact_method_id=$2 AND (sent_at IS NOT NULL OR provider_msg_id IS NOT NULL OR last_status IN ('sent','delivered','queued_remotely'))`, alertID, h.UUID(cm)).Scan(&n))
	require.Zero(t, n)
}

func TestOutboundRecipientSameOrganization(t *testing.T) {
	for _, direct := range []bool{false, true} {
		t.Run(fmt.Sprint(direct), func(t *testing.T) {
			h, db := t1New(t, false, direct)
			id := t1Alert(t, h, db, "D08 positive same org")
			t1Receive(t, h, "target", "D08 positive")
			t1Receive(t, h, "control", "D08 positive")
			var n int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM outgoing_messages WHERE alert_id=$1 AND last_status='sent' AND sent_at IS NOT NULL`, id).Scan(&n))
			require.Equal(t, 2, n)
			t1Snapshot(t, db, "positive-final")
			t1Sink(t, h, "sink-final")
		})
	}
}
