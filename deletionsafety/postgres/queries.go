package postgres

import (
	"errors"
	"fmt"
	"strings"

	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/util/sqlutil"
)

// Only safe relational identities are projected. In particular neither the
// integration credential selector nor Session credential identity is selected.
const userOrganizations = `WITH user_org AS (
 SELECT u.id AS user_id, o.id AS organization_id, u.role AS user_role, a.organization_role
 FROM public.users u JOIN public.user_organization_assignments a ON a.user_id=u.id
 JOIN public.organizations o ON o.id=a.effective_organization_id
  AND o.classification=a.effective_organization_classification
 LEFT JOIN public.normal_organizations n ON n.organization_id=o.id
 WHERE u.role IN ('user','admin') AND (
  (o.classification='NORMAL' AND n.organization_id=a.effective_normal_organization_id
   AND a.mapping_outcome='EXACTLY_ONE' AND a.matched_count=1
   AND a.organization_role IN ('ORG_ADMIN','ORG_MEMBER')) OR
  (o.classification='DEFAULT' AND o.id='296e2656-7221-53fe-bd0a-832d24ccfd03'
   AND a.effective_normal_organization_id IS NULL AND a.organization_role='NONE'
   AND ((a.mapping_outcome='ZERO' AND a.matched_count=0) OR
        (a.mapping_outcome='MULTIPLE' AND a.matched_count>1)))
 )) `

var identityQueries = map[ds.ResourceKind]string{
	ds.ResourceService:          `SELECT organization_id::text FROM public.services WHERE id=$1::uuid`,
	ds.ResourceEscalationPolicy: `SELECT organization_id::text FROM public.escalation_policies WHERE id=$1::uuid`,
	ds.ResourceSchedule:         `SELECT organization_id::text FROM public.schedules WHERE id=$1::uuid`,
	ds.ResourceRotation:         `SELECT organization_id::text FROM public.rotations WHERE id=$1::uuid`,
	ds.ResourceUser:             `SELECT organization_id::text FROM user_org WHERE user_id=$1::uuid`,
	ds.ResourceContactMethod:    `SELECT u.organization_id::text FROM public.user_contact_methods c LEFT JOIN user_org u ON u.user_id=c.user_id WHERE c.id=$1::uuid`,
	ds.ResourceNotificationRule: `SELECT u.organization_id::text FROM public.user_notification_rules r JOIN public.user_contact_methods c ON c.id=r.contact_method_id AND c.user_id=r.user_id LEFT JOIN user_org u ON u.user_id=r.user_id WHERE r.id=$1::uuid`,
	ds.ResourceIntegrationKey:   `SELECT s.organization_id::text FROM public.integration_keys k LEFT JOIN public.services s ON s.id=k.service_id WHERE k.audit_resource_id=$1::uuid`,
	ds.ResourceUserOverride:     `SELECT s.organization_id::text FROM public.user_overrides o LEFT JOIN public.schedules s ON s.id=o.tgt_schedule_id WHERE o.id=$1::uuid`,
}

var errUnsupported = errors.New("unsupported dependency projection")

var ownershipQueries = map[ds.ResourceKind]struct {
	kind  ds.ResourceKind
	query string
}{
	ds.ResourceContactMethod:    {ds.ResourceUser, `SELECT user_id::text FROM public.user_contact_methods WHERE id=$1::uuid`},
	ds.ResourceNotificationRule: {ds.ResourceUser, `SELECT user_id::text FROM public.user_notification_rules WHERE id=$1::uuid`},
	ds.ResourceIntegrationKey:   {ds.ResourceService, `SELECT service_id::text FROM public.integration_keys WHERE audit_resource_id=$1::uuid`},
	ds.ResourceUserOverride:     {ds.ResourceSchedule, `SELECT tgt_schedule_id::text FROM public.user_overrides WHERE id=$1::uuid`},
}

var referenceQueries = map[ds.ResourceKind]string{
	ds.ResourceAlert:                   `SELECT a.id::text,s.organization_id::text FROM public.alerts a LEFT JOIN public.services s ON s.id=a.service_id WHERE a.id=ANY($1::bigint[])`,
	ds.ResourceEscalationPolicyStep:    `SELECT st.id::text,ep.organization_id::text FROM public.escalation_policy_steps st LEFT JOIN public.escalation_policies ep ON ep.id=st.escalation_policy_id WHERE st.id=ANY($1::uuid[])`,
	ds.ResourceNotificationPolicyCycle: `SELECT cy.id::text,u.organization_id::text FROM public.notification_policy_cycles cy LEFT JOIN public.alerts a ON a.id=cy.alert_id LEFT JOIN public.services s ON s.id=a.service_id LEFT JOIN user_org u ON u.user_id=cy.user_id AND u.organization_id=s.organization_id WHERE cy.id=ANY($1::uuid[])`,
	ds.ResourceVerificationState:       `SELECT v.id::text,u.organization_id::text FROM public.user_verification_codes v LEFT JOIN public.user_contact_methods cm ON cm.id=v.contact_method_id LEFT JOIN user_org u ON u.user_id=cm.user_id WHERE v.id=ANY($1::uuid[])`,
	ds.ResourceAlertLog:                `SELECT l.id::text,s.organization_id::text FROM public.alert_logs l LEFT JOIN public.alerts a ON a.id=l.alert_id LEFT JOIN public.services s ON s.id=a.service_id WHERE l.id=ANY($1::bigint[])`,
	ds.ResourceOutgoingMessage:         `SELECT m.id::text,COALESCE(s.organization_id,u.organization_id)::text FROM public.outgoing_messages m LEFT JOIN public.services s ON s.id=m.service_id LEFT JOIN public.user_contact_methods cm ON cm.id=m.contact_method_id AND cm.user_id=m.user_id LEFT JOIN user_org u ON u.user_id=cm.user_id WHERE m.id=ANY($1::uuid[])`,
	ds.ResourceNotificationChannel:     `SELECT id::text,''::text FROM public.notification_channels WHERE id=ANY($1::uuid[])`,
	ds.ResourceService:                 `SELECT id::text,organization_id::text FROM public.services WHERE id=ANY($1::uuid[])`,
	ds.ResourceEscalationPolicy:        `SELECT id::text,organization_id::text FROM public.escalation_policies WHERE id=ANY($1::uuid[])`,
	ds.ResourceSchedule:                `SELECT id::text,organization_id::text FROM public.schedules WHERE id=ANY($1::uuid[])`,
	ds.ResourceRotation:                `SELECT id::text,organization_id::text FROM public.rotations WHERE id=ANY($1::uuid[])`,
	ds.ResourceUser:                    `SELECT user_id::text,organization_id::text FROM user_org WHERE user_id=ANY($1::uuid[])`,
	ds.ResourceContactMethod:           `SELECT c.id::text,u.organization_id::text FROM public.user_contact_methods c LEFT JOIN user_org u ON u.user_id=c.user_id WHERE c.id=ANY($1::uuid[])`,
	ds.ResourceNotificationRule:        `SELECT r.id::text,u.organization_id::text FROM public.user_notification_rules r LEFT JOIN public.user_contact_methods c ON c.id=r.contact_method_id AND c.user_id=r.user_id LEFT JOIN user_org u ON u.user_id=r.user_id AND c.id IS NOT NULL WHERE r.id=ANY($1::uuid[])`,
	ds.ResourceIntegrationKey:          `SELECT k.audit_resource_id::text,s.organization_id::text FROM public.integration_keys k LEFT JOIN public.services s ON s.id=k.service_id WHERE k.audit_resource_id=ANY($1::uuid[])`,
	ds.ResourceUserOverride:            `SELECT o.id::text,s.organization_id::text FROM public.user_overrides o LEFT JOIN public.schedules s ON s.id=o.tgt_schedule_id WHERE o.id=ANY($1::uuid[])`,
}

// These real schema relationships have no accepted V1 Resource/Relationship
// pair, or contain a legacy credential boundary. Do not invent a policy or
// disguise their presence as complete empty coverage. Only existence is read.
var unsupportedQueries = map[ds.ResourceKind]string{
	ds.ResourceService:             `SELECT EXISTS(SELECT 1 FROM public.labels WHERE tgt_service_id=ANY($1::uuid[])) OR EXISTS(SELECT 1 FROM public.heartbeat_monitors WHERE service_id=ANY($1::uuid[])) OR EXISTS(SELECT 1 FROM public.twilio_sms_callbacks WHERE service_id=ANY($1::uuid[]))`,
	ds.ResourceEscalationPolicy:    `SELECT EXISTS(SELECT 1 FROM public.labels WHERE tgt_ep_id=ANY($1::uuid[]))`,
	ds.ResourceSchedule:            `SELECT EXISTS(SELECT 1 FROM public.labels WHERE tgt_schedule_id=ANY($1::uuid[])) OR EXISTS(SELECT 1 FROM public.user_calendar_subscriptions WHERE schedule_id=ANY($1::uuid[]))`,
	ds.ResourceRotation:            `SELECT EXISTS(SELECT 1 FROM public.labels WHERE tgt_rotation_id=ANY($1::uuid[]))`,
	ds.ResourceRotationParticipant: `SELECT EXISTS(SELECT 1 FROM public.rotation_state WHERE rotation_participant_id=ANY($1::uuid[]))`,
	ds.ResourceRotationState:       `SELECT EXISTS(SELECT 1 FROM public.rotation_state WHERE id=ANY($1::bigint[]))`,
	ds.ResourceUser:                `SELECT EXISTS(SELECT 1 FROM public.user_slack_data WHERE id=ANY($1::uuid[])) OR EXISTS(SELECT 1 FROM public.user_calendar_subscriptions WHERE user_id=ANY($1::uuid[]))`,
	ds.ResourceAlert:               `SELECT EXISTS(SELECT 1 FROM public.twilio_sms_callbacks WHERE alert_id=ANY($1::bigint[])) OR EXISTS(SELECT 1 FROM public.outgoing_messages WHERE status_alert_ids && $1::bigint[])`,
	ds.ResourceOutgoingMessage:     `SELECT EXISTS(SELECT 1 FROM public.outgoing_messages WHERE id=ANY($1::uuid[]) AND status_alert_ids IS NOT NULL)`,
	ds.ResourceIntegrationKey:      `SELECT EXISTS(SELECT 1 FROM public.uik_config cfg JOIN public.integration_keys k ON k.id=cfg.id WHERE k.audit_resource_id=ANY($1::uuid[]))`,
}

func (c *collector) collectKind(kind ds.ResourceKind, ids []string) error {
	rotationOwned := c.rotationRoot != "" && (kind == ds.ResourceRotationParticipant || kind == ds.ResourceRotationState)
	if query := unsupportedQueries[kind]; query != "" && !rotationOwned {
		var present bool
		if err := c.queryRow(query, sqlutil.StringArray(ids)).Scan(&present); err != nil {
			return err
		}
		if present {
			return errUnsupported
		}
	}
	if kind == ds.ResourceRotation && c.rotationRoot != "" {
		if err := c.validateRotation(ids); err != nil {
			return err
		}
	}
	if kind == ds.ResourceSchedule || kind == ds.ResourceUser {
		if err := c.readScheduleData(kind, ids); err != nil {
			if kind == ds.ResourceUser && !c.global && err != errUnsupported {
				return unavailable()
			}
			return err
		}
	}
	for _, p := range projections(kind) {
		if err := c.read(p, ids, numericIdentity(kind)); err != nil {
			return err
		}
	}
	return nil
}

func numericIdentity(kind ds.ResourceKind) bool {
	switch kind {
	case ds.ResourceAlert, ds.ResourceEscalationPolicyState, ds.ResourcePendingSignal, ds.ResourceRotationState,
		ds.ResourceScheduleHistory, ds.ResourceEscalationHistory, ds.ResourceFavorite, ds.ResourceAuthSubject,
		ds.ResourceBasicAuthLink, ds.ResourceAlertData, ds.ResourceAlertFeedback, ds.ResourceAlertMetrics,
		ds.ResourceAlertStatusSubscription, ds.ResourceMessageStatusHistory, ds.ResourceAlertLog:
		return true
	default:
		return false
	}
}

func edge(rel ds.RelationshipKind, target, ref ds.ResourceKind, from, filter, tid, rid, org string) projection {
	return projection{relation: rel, target: target, referencing: ref, from: from, filter: filter, targetID: tid, referenceID: rid, organization: org}
}

func owned(p projection, parent, owner ds.ResourceKind, pid, oid string) projection {
	p.parent, p.owner, p.parentID, p.ownerID = parent, owner, pid, oid
	return p
}

const actionFrom = `public.escalation_policy_actions a LEFT JOIN public.escalation_policy_steps st ON st.id=a.escalation_policy_step_id LEFT JOIN public.escalation_policies ep ON ep.id=st.escalation_policy_id`
const ruleFrom = `public.schedule_rules r LEFT JOIN public.schedules s ON s.id=r.schedule_id`
const participantFrom = `public.rotation_participants p LEFT JOIN public.rotations r ON r.id=p.rotation_id`
const overrideFrom = `public.user_overrides o LEFT JOIN public.schedules s ON s.id=o.tgt_schedule_id`
const cycleFrom = `public.notification_policy_cycles cy LEFT JOIN public.alerts a ON a.id=cy.alert_id LEFT JOIN public.services s ON s.id=a.service_id LEFT JOIN user_org u ON u.user_id=cy.user_id AND u.organization_id=s.organization_id`
const stateFrom = `public.escalation_policy_state es LEFT JOIN public.alerts a ON a.id=es.alert_id LEFT JOIN public.services s ON s.id=es.service_id LEFT JOIN public.escalation_policies ep ON ep.id=es.escalation_policy_id AND ep.organization_id=s.organization_id`

func actions(target ds.ResourceKind, column string, outgoing bool) projection {
	filter := "a." + column
	if outgoing {
		filter = "a.id"
	}
	p := owned(edge(ds.RelationshipActionTarget, target, ds.ResourceEscalationPolicyAction, actionFrom, filter, "a."+column, "a.id", "ep.organization_id"), ds.ResourceEscalationPolicyStep, ds.ResourceEscalationPolicy, "st.id", "ep.id")
	p.referenceKind, p.reference = number(target), "a."+column
	// The predicate excludes other typed targets without filtering broken parent
	// joins. A missing parent is a NULL scope and fails closed in the reader.
	p.from += fmt.Sprintf(" AND a.%s IS NOT NULL", column)
	return p
}

func rules(target ds.ResourceKind, column string, outgoing bool) projection {
	filter := "r." + column
	if outgoing {
		filter = "r.id"
	}
	p := owned(edge(ds.RelationshipRuleTarget, target, ds.ResourceScheduleRule, ruleFrom, filter, "r."+column, "r.id", "s.organization_id"), ds.ResourceSchedule, ds.ResourceSchedule, "s.id", "s.id")
	p.referenceKind, p.reference = number(target), "r."+column
	return p
}

func participants(outgoing bool) projection {
	filter := "p.user_id"
	if outgoing {
		filter = "p.id"
	}
	p := owned(edge(ds.RelationshipParticipantUser, ds.ResourceUser, ds.ResourceRotationParticipant, participantFrom, filter, "p.user_id", "p.id", "r.organization_id"), ds.ResourceRotation, ds.ResourceRotation, "r.id", "r.id")
	p.position = "p.position"
	p.referenceKind, p.reference = number(ds.ResourceUser), "p.user_id"
	return p
}

func overrides(rel ds.RelationshipKind, target ds.ResourceKind, column string, outgoing bool) projection {
	filter := "o." + column
	if outgoing {
		filter = "o.id"
	}
	p := owned(edge(rel, target, ds.ResourceUserOverride, overrideFrom, filter, "o."+column, "o.id", "s.organization_id"), ds.ResourceSchedule, ds.ResourceSchedule, "s.id", "s.id")
	p.start, p.end = "o.start_time", "o.end_time"
	return p
}

func projections(kind ds.ResourceKind) []projection {
	var out []projection
	add := func(p projection) { out = append(out, p) }
	switch kind {
	case ds.ResourceService:
		add(edge(ds.RelationshipRetainedPolicy, kind, ds.ResourceEscalationPolicy, `public.services s LEFT JOIN public.escalation_policies ep ON ep.id=s.escalation_policy_id`, "s.id", "s.id", "ep.id", "ep.organization_id"))
		p := edge(ds.RelationshipServiceAlert, kind, ds.ResourceAlert, `public.alerts a LEFT JOIN public.services s ON s.id=a.service_id`, "a.service_id", "a.service_id", "a.id", "s.organization_id")
		p.alert = "a.status"
		add(p)
		add(owned(edge(ds.RelationshipServiceIntegrationKey, kind, ds.ResourceIntegrationKey, `public.integration_keys k LEFT JOIN public.services s ON s.id=k.service_id`, "k.service_id", "k.service_id", "k.audit_resource_id", "s.organization_id"), kind, kind, "s.id", "s.id"))
		add(edge(ds.RelationshipServiceState, kind, ds.ResourceEscalationPolicyState, stateFrom, "es.service_id", "es.service_id", "es.id", "ep.organization_id"))
	case ds.ResourceEscalationPolicy:
		add(edge(ds.RelationshipServicePolicy, kind, ds.ResourceService, `public.services s`, "s.escalation_policy_id", "s.escalation_policy_id", "s.id", "s.organization_id"))
		// Open Alert evidence also follows the real Service FK when runtime
		// state is absent. The target stays Service: no synthetic Policy->Alert
		// relationship or additional removal permission is introduced.
		p := edge(ds.RelationshipServiceAlert, ds.ResourceService, ds.ResourceAlert, `public.alerts a LEFT JOIN public.services s ON s.id=a.service_id JOIN LATERAL (SELECT 1 WHERE a.status<>'closed') open_alert ON true`, "s.escalation_policy_id", "a.service_id", "a.id", "s.organization_id")
		p.alert = "a.status"
		add(p)
		add(owned(edge(ds.RelationshipPolicyStep, kind, ds.ResourceEscalationPolicyStep, `public.escalation_policy_steps st LEFT JOIN public.escalation_policies ep ON ep.id=st.escalation_policy_id`, "st.escalation_policy_id", "st.escalation_policy_id", "st.id", "ep.organization_id"), kind, kind, "ep.id", "ep.id"))
		add(owned(edge(ds.RelationshipPolicyAction, kind, ds.ResourceEscalationPolicyAction, actionFrom, "st.escalation_policy_id", "st.escalation_policy_id", "a.id", "ep.organization_id"), ds.ResourceEscalationPolicyStep, kind, "st.id", "ep.id"))
	case ds.ResourceEscalationPolicyStep:
		add(owned(edge(ds.RelationshipStepAction, kind, ds.ResourceEscalationPolicyAction, actionFrom, "a.escalation_policy_step_id", "a.escalation_policy_step_id", "a.id", "ep.organization_id"), kind, ds.ResourceEscalationPolicy, "st.id", "ep.id"))
	case ds.ResourceEscalationPolicyAction:
		for _, t := range []struct {
			k   ds.ResourceKind
			col string
		}{{ds.ResourceUser, "user_id"}, {ds.ResourceSchedule, "schedule_id"}, {ds.ResourceRotation, "rotation_id"}} {
			p := actions(t.k, t.col, true)
			p.from = actionFrom
			p.filter = "a.id"
			p.from += " JOIN LATERAL (SELECT 1 WHERE a." + t.col + " IS NOT NULL) nonnull ON true"
			add(p)
		}
		add(edge(ds.RelationshipRetainedChannel, kind, ds.ResourceNotificationChannel, actionFrom+` JOIN public.notification_channels ch ON ch.id=a.channel_id`, "a.id", "a.id", "ch.id", "ep.organization_id"))
	case ds.ResourceSchedule:
		add(actions(kind, "schedule_id", false))
		p := owned(edge(ds.RelationshipScheduleRule, kind, ds.ResourceScheduleRule, ruleFrom, "r.schedule_id", "r.schedule_id", "r.id", "s.organization_id"), kind, kind, "s.id", "s.id")
		p.referenceKind = "CASE WHEN r.tgt_user_id IS NOT NULL THEN " + number(ds.ResourceUser) + " ELSE " + number(ds.ResourceRotation) + " END"
		p.reference = "COALESCE(r.tgt_user_id,r.tgt_rotation_id)"
		add(p)
		add(overrides(ds.RelationshipScheduleOverride, kind, "tgt_schedule_id", false))
	case ds.ResourceScheduleRule:
		for _, t := range []struct {
			k   ds.ResourceKind
			col string
		}{{ds.ResourceUser, "tgt_user_id"}, {ds.ResourceRotation, "tgt_rotation_id"}} {
			p := rules(t.k, t.col, true)
			p.from += " JOIN LATERAL (SELECT 1 WHERE r." + t.col + " IS NOT NULL) nonnull ON true"
			add(p)
		}
	case ds.ResourceRotation:
		add(actions(kind, "rotation_id", false))
		add(rules(kind, "tgt_rotation_id", false))
		p := owned(edge(ds.RelationshipRotationParticipant, kind, ds.ResourceRotationParticipant, participantFrom, "p.rotation_id", "p.rotation_id", "p.id", "r.organization_id"), kind, kind, "r.id", "r.id")
		p.position = "p.position"
		p.referenceKind, p.reference = number(ds.ResourceUser), "p.user_id"
		add(p)
		p = owned(edge(ds.RelationshipRotationState, kind, ds.ResourceRotationState,
			`public.rotation_state rs LEFT JOIN public.rotations r ON r.id=rs.rotation_id LEFT JOIN public.rotation_participants p ON p.id=rs.rotation_participant_id AND p.rotation_id=rs.rotation_id AND p.position=rs.position`,
			"rs.rotation_id", "rs.rotation_id", "rs.id", "r.organization_id"), kind, kind, "r.id", "r.id")
		p.position, p.shiftStart, p.runtimeVersion = "rs.position", "rs.shift_start", "rs.version"
		p.referenceKind, p.reference = number(ds.ResourceRotationParticipant), "p.id"
		add(p)
	case ds.ResourceRotationParticipant:
		add(participants(true))
	case ds.ResourceUser:
		add(actions(kind, "user_id", false))
		add(rules(kind, "tgt_user_id", false))
		add(participants(false))
		add(overrides(ds.RelationshipOverrideAddUser, kind, "add_user_id", false))
		add(overrides(ds.RelationshipOverrideRemoveUser, kind, "remove_user_id", false))
		add(owned(edge(ds.RelationshipUserContact, kind, ds.ResourceContactMethod, `public.user_contact_methods cm LEFT JOIN user_org u ON u.user_id=cm.user_id`, "cm.user_id", "cm.user_id", "cm.id", "u.organization_id"), kind, kind, "cm.user_id", "cm.user_id"))
		add(owned(edge(ds.RelationshipUserNotificationRule, kind, ds.ResourceNotificationRule, `public.user_notification_rules nr LEFT JOIN user_org u ON u.user_id=nr.user_id`, "nr.user_id", "nr.user_id", "nr.id", "u.organization_id"), kind, kind, "nr.user_id", "nr.user_id"))
		p := edge(ds.RelationshipUserCycle, kind, ds.ResourceNotificationPolicyCycle, cycleFrom, "cy.user_id", "cy.user_id", "cy.id", "u.organization_id")
		p.alert = "a.status"
		p.referenceKind, p.reference = number(ds.ResourceAlert), "a.id"
		add(p)
		add(edge(ds.RelationshipUserOrganization, kind, ds.ResourceOrganizationAssignment, `public.user_organization_assignments a LEFT JOIN user_org u ON u.user_id=a.user_id`, "a.user_id", "a.user_id", "a.user_id", "u.organization_id"))
		for _, t := range []struct {
			table, id string
			k         ds.ResourceKind
		}{{"auth_subjects", "id", ds.ResourceAuthSubject}, {"auth_user_sessions", "audit_resource_id", ds.ResourceUserSession}, {"auth_basic_users", "id", ds.ResourceBasicAuthLink}} {
			add(edge(ds.RelationshipUserIdentity, kind, t.k, "public."+t.table+" ident LEFT JOIN user_org u ON u.user_id=ident.user_id", "ident.user_id", "ident.user_id", "ident."+t.id, "u.organization_id"))
		}
		for _, t := range []struct {
			col string
			rel ds.RelationshipKind
		}{{"created_by", ds.RelationshipKeyCreator}, {"updated_by", ds.RelationshipKeyUpdater}, {"deleted_by", ds.RelationshipKeyDeleter}} {
			add(edge(t.rel, kind, ds.ResourceLegacyKeyAttribution, "public.gql_api_keys k LEFT JOIN user_org u ON u.user_id=k."+t.col, "k."+t.col, "k."+t.col, "k.id", "u.organization_id"))
		}
		add(edge(ds.RelationshipUserLog, kind, ds.ResourceAlertLog, `public.alert_logs l LEFT JOIN user_org u ON u.user_id=l.sub_user_id`, "l.sub_user_id", "l.sub_user_id", "l.id", "u.organization_id"))
	case ds.ResourceUserOverride:
		p := edge(ds.RelationshipOverrideCoverage, kind, ds.ResourceSchedule, overrideFrom, "o.id", "o.id", "s.id", "s.organization_id")
		p.start, p.end = "o.start_time", "o.end_time"
		add(p)
		for _, t := range []struct {
			col string
			rel ds.RelationshipKind
		}{{"add_user_id", ds.RelationshipOverrideAddUser}, {"remove_user_id", ds.RelationshipOverrideRemoveUser}} {
			p := overrides(t.rel, ds.ResourceUser, t.col, true)
			p.from += " JOIN LATERAL (SELECT 1 WHERE o." + t.col + " IS NOT NULL) nonnull ON true"
			add(p)
		}
	case ds.ResourceIntegrationKey:
		add(edge(ds.RelationshipIntegrationSource, kind, ds.ResourceService, `public.integration_keys k LEFT JOIN public.services s ON s.id=k.service_id`, "k.audit_resource_id", "k.audit_resource_id", "s.id", "s.organization_id"))
		add(edge(ds.RelationshipIntegrationLog, kind, ds.ResourceAlertLog, `public.integration_keys k JOIN public.alert_logs l ON l.sub_integration_key_id=k.id LEFT JOIN public.services s ON s.id=k.service_id`, "k.audit_resource_id", "k.audit_resource_id", "l.id", "s.organization_id"))
	case ds.ResourceContactMethod, ds.ResourceNotificationRule:
		out = append(out, contactProjections(kind)...)
	}
	if column, ok := map[ds.ResourceKind]string{ds.ResourceService: "service_id", ds.ResourceEscalationPolicy: "escalation_policy_id", ds.ResourceSchedule: "schedule_id", ds.ResourceContactMethod: "contact_method_id", ds.ResourceUser: "user_id", ds.ResourceAlert: "alert_id", ds.ResourceNotificationPolicyCycle: "cycle_id", ds.ResourceVerificationState: "user_verification_code_id"}[kind]; ok {
		// A message's User or Channel must be real; nullable/missing owner joins
		// remain unavailable. No destination or provider/status text is selected.
		from := `public.outgoing_messages m LEFT JOIN public.services s ON s.id=m.service_id LEFT JOIN public.schedules sc ON sc.id=m.schedule_id LEFT JOIN public.escalation_policies ep ON ep.id=m.escalation_policy_id LEFT JOIN user_org u ON u.user_id=m.user_id`
		add(edge(ds.RelationshipOutgoingMessage, kind, ds.ResourceOutgoingMessage, from, "m."+column, "m."+column, "m.id", "COALESCE(s.organization_id,sc.organization_id,ep.organization_id,u.organization_id)"))
	}
	if kind == ds.ResourceService || kind == ds.ResourceOutgoingMessage {
		column := "service_id"
		if kind == ds.ResourceOutgoingMessage {
			column = "message_id"
		}
		add(edge(ds.RelationshipPendingSignal, kind, ds.ResourcePendingSignal, `public.pending_signals p LEFT JOIN public.services s ON s.id=p.service_id`, "p."+column, "p."+column, "p.id", "s.organization_id"))
	}
	if kind == ds.ResourceOutgoingMessage {
		add(edge(ds.RelationshipMessageStatus, kind, ds.ResourceMessageStatusHistory, `public.message_status_history h LEFT JOIN public.outgoing_messages m ON m.id=h.message_id LEFT JOIN user_org u ON u.user_id=m.user_id LEFT JOIN public.services s ON s.id=m.service_id`, "h.message_id", "h.message_id", "h.id", "COALESCE(u.organization_id,s.organization_id)"))
	}
	if kind == ds.ResourceEscalationPolicy || kind == ds.ResourceEscalationPolicyStep {
		column := "escalation_policy_id"
		if kind == ds.ResourceEscalationPolicyStep {
			column = "escalation_policy_step_id"
		}
		p := edge(ds.RelationshipExecutionState, kind, ds.ResourceEscalationPolicyState, stateFrom, "es."+column, "es."+column, "es.id", "ep.organization_id")
		p.alert = "a.status"
		p.referenceKind, p.reference = number(ds.ResourceAlert), "a.id"
		add(p)
	}
	if column, ok := map[ds.ResourceKind]string{ds.ResourceService: "tgt_service_id", ds.ResourceEscalationPolicy: "tgt_escalation_policy_id", ds.ResourceSchedule: "tgt_schedule_id", ds.ResourceRotation: "tgt_rotation_id", ds.ResourceUser: "tgt_user_id"}[kind]; ok {
		add(edge(ds.RelationshipFavorite, kind, ds.ResourceFavorite, `public.user_favorites f LEFT JOIN user_org u ON u.user_id=f.user_id`, "f."+column, "f."+column, "f.id", "u.organization_id"))
	}
	if kind == ds.ResourceUser {
		add(edge(ds.RelationshipFavoriteOwner, kind, ds.ResourceFavorite, `public.user_favorites f LEFT JOIN user_org u ON u.user_id=f.user_id`, "f.user_id", "f.user_id", "f.id", "u.organization_id"))
	}
	if kind == ds.ResourceSchedule || kind == ds.ResourceUser {
		column := "schedule_id"
		if kind == ds.ResourceUser {
			column = "user_id"
		}
		add(edge(ds.RelationshipScheduleHistory, kind, ds.ResourceScheduleHistory, `public.schedule_on_call_users h LEFT JOIN public.schedules s ON s.id=h.schedule_id`, "h."+column, "h."+column, "h.id", "s.organization_id"))
	}
	if kind == ds.ResourceEscalationPolicy || kind == ds.ResourceEscalationPolicyStep || kind == ds.ResourceUser {
		filter, tid := "st.escalation_policy_id", "st.escalation_policy_id"
		if kind == ds.ResourceEscalationPolicyStep {
			filter, tid = "h.ep_step_id", "h.ep_step_id"
		}
		if kind == ds.ResourceUser {
			filter, tid = "h.user_id", "h.user_id"
		}
		add(edge(ds.RelationshipEscalationHistory, kind, ds.ResourceEscalationHistory, `public.ep_step_on_call_users h LEFT JOIN public.escalation_policy_steps st ON st.id=h.ep_step_id LEFT JOIN public.escalation_policies ep ON ep.id=st.escalation_policy_id`, filter, tid, "h.id", "ep.organization_id"))
	}
	if kind == ds.ResourceAlert {
		for _, t := range []struct {
			table string
			ref   ds.ResourceKind
			rel   ds.RelationshipKind
		}{{"alert_data", ds.ResourceAlertData, ds.RelationshipAlertData}, {"alert_feedback", ds.ResourceAlertFeedback, ds.RelationshipAlertFeedback}, {"alert_metrics", ds.ResourceAlertMetrics, ds.RelationshipAlertMetrics}, {"alert_status_subscriptions", ds.ResourceAlertStatusSubscription, ds.RelationshipAlertSubscription}, {"notification_policy_cycles", ds.ResourceNotificationPolicyCycle, ds.RelationshipAlertCycle}, {"escalation_policy_state", ds.ResourceEscalationPolicyState, ds.RelationshipAlertState}, {"alert_logs", ds.ResourceAlertLog, ds.RelationshipAlertLog}} {
			add(edge(t.rel, kind, t.ref, "public."+t.table+" child LEFT JOIN public.alerts a ON a.id=child.alert_id LEFT JOIN public.services s ON s.id=a.service_id", "child.alert_id", "child.alert_id", "child.id", "s.organization_id"))
		}
	}
	return out
}

func contactProjections(kind ds.ResourceKind) []projection {
	var out []projection
	add := func(p projection) { out = append(out, p) }
	const nrFrom = `public.user_notification_rules nr LEFT JOIN public.user_contact_methods cm ON cm.id=nr.contact_method_id LEFT JOIN user_org u ON u.user_id=nr.user_id AND cm.user_id=nr.user_id`
	const cmFrom = `public.user_contact_methods cm LEFT JOIN user_org u ON u.user_id=cm.user_id`
	const openCycle = `EXISTS(SELECT 1 FROM public.notification_policy_cycles cy JOIN public.alerts a ON a.id=cy.alert_id WHERE cy.user_id=cm.user_id AND a.status<>'closed')`
	if kind == ds.ResourceContactMethod {
		p := owned(edge(ds.RelationshipContactNotificationRule, kind, ds.ResourceNotificationRule, nrFrom, "nr.contact_method_id", "nr.contact_method_id", "nr.id", "u.organization_id"), ds.ResourceUser, ds.ResourceUser, "nr.user_id", "nr.user_id")
		p.sameOwner = "nr.user_id=cm.user_id"
		p.referenceKind, p.reference = number(ds.ResourceContactMethod), "cm.id"
		add(p)
		add(edge(ds.RelationshipStatusContact, kind, ds.ResourceUser, `public.users usr LEFT JOIN user_org u ON u.user_id=usr.id`, "usr.alert_status_log_contact_method_id", "usr.alert_status_log_contact_method_id", "usr.id", "u.organization_id"))
		p = edge(ds.RelationshipImmediateRoute, kind, ds.ResourceUser, cmFrom, "cm.id", "cm.id", "cm.user_id", "u.organization_id")
		p.risk = `1 + CASE WHEN NOT cm.disabled AND NOT cm.pending
		 AND EXISTS(SELECT 1 FROM public.user_notification_rules nr WHERE nr.contact_method_id=cm.id AND nr.user_id=cm.user_id AND nr.delay_minutes=0)
		 AND NOT EXISTS(SELECT 1 FROM public.user_notification_rules other JOIN public.user_contact_methods oc ON oc.id=other.contact_method_id AND oc.user_id=other.user_id WHERE other.user_id=cm.user_id AND other.delay_minutes=0 AND NOT oc.disabled AND NOT oc.pending AND oc.id<>cm.id)
		 THEN 1 ELSE 0 END + CASE WHEN ` + openCycle + ` THEN 2 ELSE 0 END`
		add(p)
		add(edge(ds.RelationshipContactAuthSubject, kind, ds.ResourceAuthSubject, `public.auth_subjects a LEFT JOIN public.user_contact_methods cm ON cm.id=a.cm_id LEFT JOIN user_org u ON u.user_id=a.user_id AND a.user_id=cm.user_id`, "a.cm_id", "a.cm_id", "a.id", "u.organization_id"))
		add(edge(ds.RelationshipVerification, kind, ds.ResourceVerificationState, `public.user_verification_codes v LEFT JOIN public.user_contact_methods cm ON cm.id=v.contact_method_id LEFT JOIN user_org u ON u.user_id=cm.user_id`, "v.contact_method_id", "v.contact_method_id", "v.id", "u.organization_id"))
		add(edge(ds.RelationshipContactSubscription, kind, ds.ResourceAlertStatusSubscription, `public.alert_status_subscriptions sub LEFT JOIN public.user_contact_methods cm ON cm.id=sub.contact_method_id LEFT JOIN user_org u ON u.user_id=cm.user_id LEFT JOIN public.alerts a ON a.id=sub.alert_id LEFT JOIN public.services s ON s.id=a.service_id AND s.organization_id=u.organization_id`, "sub.contact_method_id", "sub.contact_method_id", "sub.id", "s.organization_id"))
	} else {
		p := edge(ds.RelationshipNotificationConfiguration, kind, ds.ResourceUser, nrFrom, "nr.id", "nr.id", "nr.user_id", "u.organization_id")
		p.risk = `1 + CASE WHEN nr.delay_minutes=0 AND NOT cm.disabled AND NOT cm.pending
		 AND NOT EXISTS(SELECT 1 FROM public.user_notification_rules other JOIN public.user_contact_methods oc ON oc.id=other.contact_method_id AND oc.user_id=other.user_id WHERE other.user_id=nr.user_id AND other.delay_minutes=0 AND NOT oc.disabled AND NOT oc.pending AND other.id<>nr.id)
		 THEN 1 ELSE 0 END + CASE WHEN ` + openCycle + ` THEN 2 ELSE 0 END`
		add(p)
		p = owned(edge(ds.RelationshipRetainedContact, kind, ds.ResourceContactMethod, nrFrom, "nr.id", "nr.id", "cm.id", "u.organization_id"), ds.ResourceUser, ds.ResourceUser, "cm.user_id", "cm.user_id")
		p.referenceKind, p.reference = number(ds.ResourceContactMethod), "cm.id"
		add(p)
	}
	return out
}

// Known retained outgoing FKs are configuration facts; they never create an
// additional cascade policy. All referenced business identities are resolved in
// batches before publication. The projection contains only safe IDs and kinds.
func projectionReferences(p projection) string {
	type ref struct {
		k  ds.ResourceKind
		id string
	}
	var refs []ref
	switch p.referencing {
	case ds.ResourceOutgoingMessage:
		refs = []ref{{ds.ResourceUser, "m.user_id"}, {ds.ResourceContactMethod, "m.contact_method_id"}, {ds.ResourceService, "m.service_id"}, {ds.ResourceEscalationPolicy, "m.escalation_policy_id"}, {ds.ResourceSchedule, "m.schedule_id"}, {ds.ResourceAlert, "m.alert_id"}, {ds.ResourceAlertLog, "m.alert_log_id"}, {ds.ResourceNotificationPolicyCycle, "m.cycle_id"}, {ds.ResourceVerificationState, "m.user_verification_code_id"}, {ds.ResourceNotificationChannel, "m.channel_id"}}
	case ds.ResourcePendingSignal:
		refs = []ref{{ds.ResourceService, "p.service_id"}, {ds.ResourceOutgoingMessage, "p.message_id"}, {ds.ResourceNotificationChannel, "p.dest_id"}}
	case ds.ResourceFavorite:
		refs = []ref{{ds.ResourceUser, "f.user_id"}, {ds.ResourceUser, "f.tgt_user_id"}, {ds.ResourceService, "f.tgt_service_id"}, {ds.ResourceSchedule, "f.tgt_schedule_id"}, {ds.ResourceRotation, "f.tgt_rotation_id"}, {ds.ResourceEscalationPolicy, "f.tgt_escalation_policy_id"}}
	case ds.ResourceScheduleHistory:
		refs = []ref{{ds.ResourceUser, "h.user_id"}, {ds.ResourceSchedule, "h.schedule_id"}}
	case ds.ResourceEscalationHistory:
		refs = []ref{{ds.ResourceUser, "h.user_id"}, {ds.ResourceEscalationPolicyStep, "h.ep_step_id"}, {ds.ResourceEscalationPolicy, "st.escalation_policy_id"}}
	case ds.ResourceUserOverride:
		refs = []ref{{ds.ResourceUser, "o.add_user_id"}, {ds.ResourceUser, "o.remove_user_id"}, {ds.ResourceSchedule, "o.tgt_schedule_id"}}
	case ds.ResourceEscalationPolicyState:
		alias := "es"
		if !strings.Contains(p.from, "state es ") {
			alias = "child"
		}
		refs = []ref{{ds.ResourceAlert, alias + ".alert_id"}, {ds.ResourceService, alias + ".service_id"}, {ds.ResourceEscalationPolicy, alias + ".escalation_policy_id"}, {ds.ResourceEscalationPolicyStep, alias + ".escalation_policy_step_id"}}
	case ds.ResourceNotificationPolicyCycle:
		alias := "cy"
		if !strings.Contains(p.from, "cycles cy ") {
			alias = "child"
		}
		refs = []ref{{ds.ResourceUser, alias + ".user_id"}, {ds.ResourceAlert, alias + ".alert_id"}}
	case ds.ResourceAuthSubject:
		alias := "ident"
		if strings.Contains(p.from, "subjects a ") {
			alias = "a"
		}
		refs = []ref{{ds.ResourceUser, alias + ".user_id"}, {ds.ResourceContactMethod, alias + ".cm_id"}}
	case ds.ResourceAlertStatusSubscription:
		alias := "sub"
		if !strings.Contains(p.from, "subscriptions sub ") {
			alias = "child"
		}
		refs = []ref{{ds.ResourceAlert, alias + ".alert_id"}, {ds.ResourceContactMethod, alias + ".contact_method_id"}, {ds.ResourceNotificationChannel, alias + ".channel_id"}}
	case ds.ResourceUserSession, ds.ResourceBasicAuthLink:
		refs = []ref{{ds.ResourceUser, "ident.user_id"}}
	}
	if len(refs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(refs))
	for _, r := range refs {
		parts = append(parts, "jsonb_build_object('Kind',"+number(r.k)+",'ID',"+r.id+"::text)")
	}
	return "jsonb_build_array(" + strings.Join(parts, ",") + ")"
}
