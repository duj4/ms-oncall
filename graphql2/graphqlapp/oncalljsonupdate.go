package graphqlapp

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/internal/oncalljsonguard"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	audit "github.com/target/goalert/schedule/oncallupdateaudit"
	"github.com/target/goalert/validation"
)

const onCallVersionDomain = updateVersionDomain + "oncall-json.v1\x00"

type onCallAssessment struct {
	event  audit.Event
	rules  []schedule.OnCallNotificationRule
	plan   ds.DeletionPlan
	digest string
}

func onCallPlan(e audit.Event, scope string) (ds.DeletionPlan, error) {
	root := updateObject(ds.ResourceSchedule, e.ScheduleID.String())
	var targets []ds.Resource
	var intents []ds.DestructiveChange
	var deps []ds.Dependency
	for _, old := range e.Before {
		var removed bool
		for _, effect := range e.Effects {
			if effect.RuleID == old.ID && audit.Destructive([]audit.Effect{effect}) {
				removed = true
			}
		}
		if !removed {
			continue
		}
		r := updateObject(ds.ResourceOnCallNotificationRule, old.ID)
		before := ds.Configuration{References: []ds.Resource{updateObject(ds.ResourceNotificationChannel, old.Channel)}}
		targets = append(targets, r)
		intents = append(intents, ds.DestructiveChange{Resource: r, Kind: ds.ChangeRelationRemoved, Before: before})
		deps = append(deps, ds.Dependency{Target: r, Referencing: root, Relationship: ds.RelationshipRemovedOnCallRule, Before: before})
	}
	if len(targets) == 0 {
		return ds.DeletionPlan{}, nil
	}
	return ds.BuildPlan(ds.PlanInput{Operation: ds.OperationSetOnCallNotificationRules, Targets: targets, Intent: intents, Collection: ds.Collection{Completeness: ds.DependenciesComplete, Checked: targets, Dependencies: deps}, ScopeFingerprint: scope}, ds.DefaultBudget())
}

// assessOnCall runs in the actual RO/RR preview or RW/RC business transaction.
// Only hashes of private destination values enter the signed manifest; none
// enter the response, audit, errors or logs. No mapping occurs here.
func (a *App) assessOnCall(ctx context.Context, tx *sql.Tx, input graphql2.SetScheduleOnCallNotificationRulesInput, locked bool) (onCallAssessment, error) {
	var s onCallAssessment
	id, err := parseUUID("ScheduleID", input.ScheduleID)
	if err != nil {
		return s, err
	}
	if a.DestReg == nil || a.NCStore == nil || a.ScheduleStore == nil {
		return s, previewUnavailable()
	}
	var ro, iso string
	if err := tx.QueryRowContext(ctx, `SELECT current_setting('transaction_read_only'),current_setting('transaction_isolation')`).Scan(&ro, &iso); err != nil {
		return s, err
	}
	if locked && (ro != "off" || iso != "read committed") || !locked && (ro != "on" || iso != "repeatable read") {
		return s, previewUnavailable()
	}
	home, err := scheduleRotationManagementAuthority(ctx, scheduleRotationManagementUpdate)
	if err != nil {
		return s, err
	}
	org := home
	if ec := executioncontext.ExecutionContextFromContext(ctx); ec != nil && ec.Privileges().PlatformAdmin() {
		org = nil
	}
	var actual uuid.UUID
	var rootState string
	readRoot := func() error {
		return tx.QueryRowContext(ctx, `SELECT organization_id,jsonb_build_array(id,organization_id,time_zone)::text FROM schedules WHERE id=$1 AND ($2::uuid IS NULL OR organization_id=$2)`, id, org).Scan(&actual, &rootState)
	}
	if err := readRoot(); err != nil {
		return s, err
	}
	if home != nil && *home != actual && len(input.Rules) > 0 {
		return s, validation.NewFieldError("Rules", "Foreign Schedule destination/channel ownership policy is not defined")
	}
	envelope, current, err := a.ScheduleStore.ReadOnCallUpdate(ctx, tx, id, locked)
	if err != nil {
		return s, err
	}
	if locked {
		if err := lockUpdateRows(ctx, tx, `SELECT id::text FROM schedules WHERE id=$1 FOR SHARE NOWAIT`, id); err != nil {
			return s, err
		}
		if err := readRoot(); err != nil {
			return s, err
		}
		if home != nil && *home != actual && len(input.Rules) > 0 {
			return s, previewUnavailable()
		}
	}
	scope, err := collector.UpdateScope(ctx, tx, actual, locked)
	if err != nil {
		return s, err
	}
	before, err := schedule.OnCallSnapshot(id, current)
	if err != nil {
		return s, err
	}
	channelState := []any{}
	// Every old channel, including removed relationships, is corroborated and
	// locked. Channel configuration changes invalidate the signed assessment.
	ids := []string{}
	for _, r := range before {
		if !slices.Contains(ids, r.Channel) {
			ids = append(ids, r.Channel)
		}
	}
	slices.Sort(ids)
	for _, channel := range ids {
		query := `SELECT dest FROM notification_channels WHERE id=$1 AND dest IS NOT NULL`
		if locked {
			query += ` FOR SHARE NOWAIT`
		}
		var d gadb.DestV1
		if err := tx.QueryRowContext(ctx, query, channel).Scan(&d); err != nil {
			return s, err
		}
		channelState = append(channelState, []any{channel, d.DestHash()})
	}
	s.rules = make([]schedule.OnCallNotificationRule, 0, len(input.Rules))
	intentState := []any{}
	for _, r := range input.Rules {
		info, err := a.DestReg.TypeInfo(ctx, r.Dest.Type)
		if err != nil {
			return s, err
		}
		if !info.IsSchedOnCallNotify() {
			return s, validation.NewFieldError("Rules.Dest.Type", "unsupported destination type")
		}
		if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
			return s, err
		}
		if err := a.DestReg.ValidateDest(ctx, r.Dest); err != nil {
			return s, err
		}
		if _, err := a.DestReg.DisplayInfo(ctx, r.Dest); err != nil {
			return s, err
		}
		channel, err := a.NCStore.LookupDestID(ctx, tx, r.Dest)
		pending := err == sql.ErrNoRows
		if err != nil && !pending {
			return s, err
		}
		hash := r.Dest.DestHash()
		if pending {
			// Stable task intent identity. It is inserted only after valid consent;
			// a raced mapping to another ID causes rollback, never silent rebinding.
			channel = uuid.NewSHA1(id, append([]byte("oncall-pending-channel-v1:"), hash[:]...))
		} else {
			query := `SELECT dest FROM notification_channels WHERE id=$1 AND dest IS NOT NULL`
			if locked {
				query += ` FOR SHARE NOWAIT`
			}
			var dest gadb.DestV1
			if err := tx.QueryRowContext(ctx, query, channel).Scan(&dest); err != nil {
				return s, err
			}
			if !dest.Equal(r.Dest) {
				return s, previewUnavailable()
			}
		}
		r.ChannelID = channel
		s.rules = append(s.rules, r.OnCallNotificationRule)
		intentState = append(intentState, []any{r.ID.String(), channel, hash, pending, r.Time, r.WeekdayFilter})
	}
	if err := schedule.PrepareOnCallNotificationRules(id, s.rules); err != nil {
		return s, err
	}
	after, err := schedule.OnCallSnapshot(id, s.rules)
	if err != nil {
		return s, err
	}
	effects, err := audit.Diff(id, before, after)
	if err != nil {
		return s, err
	}
	p := scheduleUpdateAuditEvent(ctx, graphql2.UpdateScheduleInput{})
	s.event = audit.Event{Version: 1, EventID: p.EventID, RequestID: p.RequestID, AttemptID: p.AttemptID, ActorKind: p.ActorKind, ActorID: p.ActorID, HomeOrganizationID: p.HomeOrganizationID, AuthoritySource: p.AuthoritySource, AuthorityRole: p.AuthorityRole, OrganizationRole: p.OrganizationRole, ScheduleID: id, OrganizationID: actual, EnvelopeID: envelope, Operation: audit.Operation, OccurredAt: time.Now(), Before: before, After: after, Effects: effects}
	s.plan, err = onCallPlan(s.event, scope)
	if err != nil {
		return s, err
	}
	manifest, err := json.Marshal([]any{ds.PolicyVersion, 1, audit.Operation, scope, rootState, id, envelope, intentState, channelState, before, after, effects, s.plan.ImpactVersion()})
	if err != nil {
		return s, err
	}
	s.digest = hexDigest(manifest)
	return s, nil
}

func encodeOnCallVersion(signer DeletionCursorSigner, digest string, at time.Time) (string, error) {
	if signer == nil {
		return "", previewUnavailable()
	}
	payload, err := json.Marshal(scheduleJSONVersion{digest, at.UnixNano()})
	if err != nil {
		return "", previewUnavailable()
	}
	sig, err := signer.Sign(append([]byte(onCallVersionDomain), payload...))
	if err != nil || len(sig) == 0 {
		return "", previewUnavailable()
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func decodeOnCallVersion(signer DeletionCursorSigner, raw string, now time.Time) (scheduleJSONVersion, error) {
	bad := func() (scheduleJSONVersion, error) {
		return scheduleJSONVersion{}, &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
	}
	if signer == nil || len(raw) > 2048 {
		return bad()
	}
	data, sig, ok := strings.Cut(raw, ".")
	if !ok {
		return bad()
	}
	payload, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return bad()
	}
	signature, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return bad()
	}
	valid, _ := signer.Verify(append([]byte(onCallVersionDomain), payload...), signature)
	if !valid {
		return bad()
	}
	var v scheduleJSONVersion
	if err := json.Unmarshal(payload, &v); err != nil || len(v.Digest) != 64 {
		return bad()
	}
	at := time.Unix(0, v.At)
	if at.After(now) || now.Sub(at) > scheduleJSONConsentTTL {
		return bad()
	}
	return v, nil
}

func (s onCallAssessment) response(version string) *graphql2.UpdateDeletionPreview {
	detail := &graphql2.OnCallJSONUpdatePreview{ContractVersion: 1, Before: []graphql2.OnCallJSONRule{}, After: []graphql2.OnCallJSONRule{}, Effects: []graphql2.OnCallJSONEffect{}}
	project := func(in []audit.Rule) []graphql2.OnCallJSONRule {
		out := []graphql2.OnCallJSONRule{}
		for _, r := range in {
			out = append(out, graphql2.OnCallJSONRule{RuleID: r.ID, ChannelID: r.Channel, Time: r.Time, Weekdays: r.Weekdays})
		}
		return out
	}
	detail.Before = project(s.event.Before)
	detail.After = project(s.event.After)
	for _, e := range s.event.Effects {
		detail.Effects = append(detail.Effects, graphql2.OnCallJSONEffect{RuleID: e.RuleID, Change: e.Change, Source: e.Source})
	}
	out := &graphql2.UpdateDeletionPreview{Operation: graphql2.DeletionOperationSetScheduleOnCallNotificationRules, Root: safeUpdateResource(updateObject(ds.ResourceSchedule, s.event.ScheduleID.String())), ImpactVersion: version, PolicyVersion: ds.PolicyVersion, Complete: true, CanProceed: true, RequiresConfirmation: audit.Destructive(s.event.Effects), Removed: []graphql2.DeletionResource{}, Impacts: []graphql2.DeletionImpact{}, OnCallJSONUpdate: detail}
	if out.RequiresConfirmation {
		out.CanProceed = s.plan.CanProceed()
		for _, v := range s.plan.Impacts() {
			out.Impacts = append(out.Impacts, graphql2.DeletionImpact{EdgeID: v.EdgeID, Target: safeUpdateResource(v.Target), ReferencingResource: safeUpdateResource(v.Referencing), Relation: previewRelationshipNames[v.Relationship], Change: previewChangeNames[v.Change], Policy: graphql2.DeletionPolicyWarning, Impact: "Existing on-call notification relationships are removed or replaced; the Schedule and Channels remain present. Exact changes are in onCallJSONUpdate.", RequiredAction: previewActionNames[v.RequiredAction], CanModifyReference: true})
		}
	}
	return out
}

func (q *Query) PreviewSetScheduleOnCallNotificationRules(ctx context.Context, input graphql2.SetScheduleOnCallNotificationRulesInput) (*graphql2.UpdateDeletionPreview, error) {
	if q.DB == nil || q.PreviewSigner == nil || hasInheritedContextTx(ctx) {
		return nil, previewUnavailable()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := q.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, previewUnavailable()
	}
	defer func() { _ = tx.Rollback() }()
	s, err := (*App)(q).assessOnCall(ctx, tx, input, false)
	if err != nil {
		return nil, safePreviewError(err)
	}
	version, err := encodeOnCallVersion(q.PreviewSigner, s.digest, time.Now())
	if err != nil {
		return nil, err
	}
	if err := tx.Rollback(); err != nil {
		return nil, previewUnavailable()
	}
	return s.response(version), nil
}

func (m *Mutation) executeOnCallJSON(ctx context.Context, input graphql2.SetScheduleOnCallNotificationRulesInput) (bool, error) {
	if _, err := parseUUID("ScheduleID", input.ScheduleID); err != nil {
		return false, err
	}
	if _, err := scheduleRotationManagementAuthority(ctx, scheduleRotationManagementUpdate); err != nil {
		return false, err
	}
	if m.DB == nil || m.ScheduleStore == nil || m.DestReg == nil || m.NCStore == nil {
		return false, previewUnavailable()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err := withContextTx(ctx, m.DB, func(ctx context.Context, tx *sql.Tx) error {
		s, err := (*App)(m).assessOnCall(ctx, tx, input, true)
		if err != nil {
			return err
		}
		c := input.Confirmation
		var version *scheduleJSONVersion
		if c != nil && c.ExpectedImpactVersion != "" {
			v, err := decodeOnCallVersion(m.PreviewSigner, c.ExpectedImpactVersion, time.Now())
			if err != nil {
				return err
			}
			version = &v
			if v.Digest != s.digest {
				return &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
			}
		}
		if audit.Destructive(s.event.Effects) {
			if c == nil || !c.AcknowledgeImpacts || version == nil {
				return &ds.DeletionSafetyError{Code: ds.DeletionConfirmationRequired}
			}
			if err := s.plan.Check(s.plan.ImpactVersion(), true); err != nil {
				return err
			}
		}
		// Re-read all locked state before issuing the capability. Derived runtime
		// state is excluded from the digest and merged fresh by the Store writer.
		fresh, err := (*App)(m).assessOnCall(ctx, tx, input, true)
		if err != nil {
			return err
		}
		if fresh.digest != s.digest {
			return &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
		}
		s = fresh
		for i, r := range input.Rules {
			actual, err := m.NCStore.MapDestToPlannedID(ctx, tx, r.Dest, s.rules[i].ChannelID)
			if err != nil {
				return err
			}
			if actual != s.rules[i].ChannelID {
				return &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
			}
			var mapped gadb.DestV1
			if err := tx.QueryRowContext(ctx, `SELECT dest FROM notification_channels WHERE id=$1 FOR SHARE NOWAIT`, actual).Scan(&mapped); err != nil {
				return err
			}
			if !mapped.Equal(r.Dest) {
				return &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
			}
		}
		guarded, err := oncalljsonguard.Bind(ctx, tx, s.event)
		if err != nil {
			return err
		}
		return m.ScheduleStore.SetOnCallNotificationRulesScoped(guarded, tx, s.event.ScheduleID, s.rules, &s.event.OrganizationID)
	})
	if err != nil {
		return false, scheduleTargetUpdateSafeError(err)
	}
	return true, nil
}
