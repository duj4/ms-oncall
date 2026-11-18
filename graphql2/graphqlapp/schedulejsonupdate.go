package graphqlapp

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/internal/schedulejsonguard"
	"github.com/target/goalert/schedule"
	audit "github.com/target/goalert/schedule/jsonupdateaudit"
	"github.com/target/goalert/validation"
)

const scheduleJSONVersionDomain = updateVersionDomain + "schedule-json.v1\x00"
const scheduleJSONConsentTTL = 5 * time.Minute

type scheduleJSONVersion struct {
	Digest string `json:"digest"`
	At     int64  `json:"at"`
}
type scheduleJSONAssessment struct {
	event             audit.Event
	requested, update schedule.TemporaryUpdate
	root              ds.Resource
	plan              ds.DeletionPlan
	digest            string
}

func scheduleJSONIntent(raw any) (uuid.UUID, schedule.TemporaryUpdate, *graphql2.DeletionSafetyConfirmationInput, error) {
	var id string
	var c *graphql2.DeletionSafetyConfirmationInput
	var u schedule.TemporaryUpdate
	switch i := raw.(type) {
	case graphql2.SetTemporaryScheduleInput:
		id = i.ScheduleID
		c = i.Confirmation
		u = schedule.TemporaryUpdate{Operation: audit.Set, Mode: "set", Temporary: schedule.TemporarySchedule{Start: i.Start.UTC(), End: i.End.UTC(), Shifts: slices.Clone(i.Shifts)}}
		for n := range u.Temporary.Shifts {
			s := &u.Temporary.Shifts[n]
			s.Start = s.Start.UTC()
			s.End = s.End.UTC()
			if v, err := uuid.Parse(s.UserID); err == nil {
				s.UserID = v.String()
			}
		}
		if i.ClearStart != nil || i.ClearEnd != nil {
			if i.ClearStart == nil {
				return uuid.Nil, u, c, validation.NewFieldError("ClearStart", "must be set if ClearEnd is set")
			}
			if i.ClearEnd == nil {
				return uuid.Nil, u, c, validation.NewFieldError("ClearEnd", "must be set if ClearStart is set")
			}
			u.Mode = "set_clear"
			u.ClearStart = i.ClearStart.UTC()
			u.ClearEnd = i.ClearEnd.UTC()
		}
	case graphql2.ClearTemporarySchedulesInput:
		id = i.ScheduleID
		c = i.Confirmation
		u = schedule.TemporaryUpdate{Operation: audit.Clear, Mode: "clear", ClearStart: i.Start.UTC(), ClearEnd: i.End.UTC()}
	default:
		return uuid.Nil, u, c, previewUnavailable()
	}
	parsed, err := parseUUID("ScheduleID", id)
	return parsed, u, c, err
}

func scheduleJSONEvent(ctx context.Context, id, org uuid.UUID, envelope int64, u schedule.TemporaryUpdate, b, a []audit.Coverage) (audit.Event, error) {
	p := scheduleUpdateAuditEvent(ctx, graphql2.UpdateScheduleInput{})
	effects, err := audit.Diff(b, a)
	if err != nil {
		return audit.Event{}, err
	}
	return audit.Event{Version: 1, EventID: p.EventID, RequestID: p.RequestID, AttemptID: p.AttemptID, ActorKind: p.ActorKind, ActorID: p.ActorID, HomeOrganizationID: p.HomeOrganizationID, AuthoritySource: p.AuthoritySource, AuthorityRole: p.AuthorityRole, OrganizationRole: p.OrganizationRole, ScheduleID: id, OrganizationID: org, EnvelopeID: envelope, Operation: u.Operation, Mode: u.Mode, OccurredAt: time.Now(), Before: b, After: a, Effects: effects}, nil
}

func scheduleJSONPlan(e audit.Event, scope string) (ds.DeletionPlan, error) {
	root := updateObject(ds.ResourceSchedule, e.ScheduleID.String())
	op := ds.OperationSetTemporarySchedule
	if e.Operation == audit.Clear {
		op = ds.OperationClearTemporarySchedules
	}
	var targets []ds.Resource
	var intents []ds.DestructiveChange
	var dependencies []ds.Dependency
	for _, effect := range e.Effects {
		if effect.Change != "coverage_removed" {
			continue
		}
		kind := ds.ResourceTemporarySchedule
		if effect.Kind == "fixed_shift" {
			kind = ds.ResourceFixedShift
		}
		raw, err := json.Marshal(effect)
		if err != nil {
			return ds.DeletionPlan{}, err
		}
		// A content locator for this event snapshot, never a persistent Shift ID.
		r := updateObject(kind, fmt.Sprintf("schedule-data:%d:coverage:%s", e.EnvelopeID, hexDigest(raw)))
		before := ds.Configuration{WindowStart: audit.Time(effect.Start), WindowEnd: audit.Time(effect.End)}
		if effect.UserID != "" {
			before.References = []ds.Resource{updateObject(ds.ResourceUser, effect.UserID)}
		}
		targets = append(targets, r)
		intents = append(intents, ds.DestructiveChange{Resource: r, Kind: ds.ChangeConfigTrimmed, Before: before})
		dependencies = append(dependencies, ds.Dependency{Target: r, Referencing: root, Relationship: ds.RelationshipChangedTemporary, Before: before})
	}
	if len(targets) == 0 {
		return ds.DeletionPlan{}, nil
	}
	// Preserve the existing per-intent 150-shift limit without truncating a
	// complete diff to the generic 100-root selector budget. The domain's
	// existing closed upper bound is 1000, and overflow still fails closed.
	budget := ds.DefaultBudget()
	budget.MaxTargets = 1000
	return ds.BuildPlan(ds.PlanInput{Operation: op, Targets: targets, Intent: intents, Collection: ds.Collection{Completeness: ds.DependenciesComplete, Checked: targets, Dependencies: dependencies}, ScopeFingerprint: scope}, budget)
}

func (a *App) assessScheduleJSON(ctx context.Context, tx *sql.Tx, id uuid.UUID, requested schedule.TemporaryUpdate, at time.Time, locked bool) (scheduleJSONAssessment, error) {
	s := scheduleJSONAssessment{root: updateObject(ds.ResourceSchedule, id.String()), requested: requested}
	var readOnly, isolation string
	if err := tx.QueryRowContext(ctx, `SELECT current_setting('transaction_read_only'),current_setting('transaction_isolation')`).Scan(&readOnly, &isolation); err != nil {
		return s, safePreviewError(err)
	}
	if locked && (readOnly != "off" || isolation != "read committed") || !locked && (readOnly != "on" || isolation != "repeatable read") {
		return s, previewUnavailable()
	}

	org, err := scheduleRotationManagementAuthority(ctx, scheduleRotationManagementUpdate)
	if err != nil {
		return s, err
	}
	if ec := executioncontext.ExecutionContextFromContext(ctx); ec != nil && ec.Privileges().PlatformAdmin() {
		org = nil
	}
	var actualOrg uuid.UUID
	var rootState string
	// Parent identity is corroborated in this same snapshot before private JSON.
	if err := tx.QueryRowContext(ctx, `SELECT organization_id,jsonb_build_array(id,organization_id,time_zone)::text FROM schedules WHERE id=$1 AND ($2::uuid IS NULL OR organization_id=$2)`, id, org).Scan(&actualOrg, &rootState); err != nil {
		return s, safePreviewError(err)
	}
	if org == nil {
		org = &actualOrg
	}
	envelope, before, err := a.ScheduleStore.ReadTemporaryUpdate(ctx, tx, id, locked)
	if err != nil {
		return s, safePreviewError(err)
	}
	if locked {
		if err := lockUpdateRows(ctx, tx, `SELECT id::text FROM schedules WHERE id=$1 FOR SHARE NOWAIT`, id); err != nil {
			return s, err
		}

		// The unlocked admission read may have preceded a parent change.
		// Re-read its scope/configuration only after owning the parent lock.
		if err := tx.QueryRowContext(ctx, `SELECT organization_id,jsonb_build_array(id,organization_id,time_zone)::text FROM schedules WHERE id=$1 AND ($2::uuid IS NULL OR organization_id=$2)`, id, org).Scan(&actualOrg, &rootState); err != nil {
			return s, safePreviewError(err)
		}
	}
	s.update, err = a.ScheduleStore.NormalizeTemporaryUpdateAt(ctx, tx, id, org, requested, at)
	if err != nil {
		return s, err
	}
	b, err := schedule.TemporaryCoverage(before)
	if err != nil {
		return s, previewUnavailable()
	}
	next, err := schedule.TemporaryCoverage(s.update.Apply(before))
	if err != nil {
		return s, previewUnavailable()
	}
	s.event, err = scheduleJSONEvent(ctx, id, actualOrg, envelope, s.update, b, next)
	if err != nil {
		return s, err
	}
	// All before AND after users, including removed references, affect scope and
	// version validity. The existing writer independently checks final bytes.
	var users []string
	for _, v := range append(slices.Clone(b), next...) {
		if v.UserID != "" && !slices.Contains(users, v.UserID) {
			users = append(users, v.UserID)
		}
	}
	slices.Sort(users)
	userState, err := a.rotationUpdateUsers(ctx, tx, actualOrg, users, locked)
	if err != nil {
		return s, err
	}
	scope, err := collector.UpdateScope(ctx, tx, actualOrg, locked)
	if err != nil {
		return s, err
	}
	s.plan, err = scheduleJSONPlan(s.event, scope)
	if err != nil {
		return s, err
	}
	manifest, err := json.Marshal([]any{ds.PolicyVersion, 1, scope, rootState, userState, id, envelope, requested, s.update, b, next, s.event.Effects, s.plan.ImpactVersion()})
	if err != nil {
		return s, previewUnavailable()
	}
	s.digest = hexDigest(manifest)
	return s, nil
}

func encodeScheduleJSONVersion(signer DeletionCursorSigner, digest string, at time.Time) (string, error) {
	if signer == nil {
		return "", previewUnavailable()
	}
	payload, err := json.Marshal(scheduleJSONVersion{digest, at.UnixNano()})
	if err != nil {
		return "", previewUnavailable()
	}
	sig, err := signer.Sign(append([]byte(scheduleJSONVersionDomain), payload...))
	if err != nil || len(sig) == 0 {
		return "", previewUnavailable()
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func decodeScheduleJSONVersion(signer DeletionCursorSigner, raw string, now time.Time) (scheduleJSONVersion, error) {
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
	valid, _ := signer.Verify(append([]byte(scheduleJSONVersionDomain), payload...), signature)
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

// Time passing can only retain old elapsed coverage or omit new elapsed
// coverage. Neither removal nor addition may extend beyond signed consent.
func scheduleJSONAttenuates(consent, actual []audit.Effect) bool {
	for _, change := range []string{"coverage_removed", "coverage_added"} {
		var approved, want []audit.Coverage
		for _, e := range consent {
			if e.Change == change {
				approved = append(approved, e.Coverage)
			}
		}
		for _, e := range actual {
			if e.Change == change {
				want = append(want, e.Coverage)
			}
		}
		diff, err := audit.Diff(approved, want)
		if err != nil {
			return false
		}
		for _, e := range diff {
			if e.Change == "coverage_added" {
				return false
			}
		}
	}
	return true
}

func jsonCoverage(v audit.Coverage) graphql2.ScheduleJSONCoverage {
	out := graphql2.ScheduleJSONCoverage{Kind: v.Kind, Start: audit.Time(v.Start), End: audit.Time(v.End)}
	if v.UserID != "" {
		id := v.UserID
		out.UserID = &id
	}
	return out
}

func (s scheduleJSONAssessment) response(version string) *graphql2.UpdateDeletionPreview {
	detail := &graphql2.ScheduleJSONUpdatePreview{ContractVersion: 1, Operation: s.event.Operation, Mode: s.event.Mode, Before: []graphql2.ScheduleJSONCoverage{}, After: []graphql2.ScheduleJSONCoverage{}, Effects: []graphql2.ScheduleJSONCoverageChange{}}
	for _, v := range s.event.Before {
		detail.Before = append(detail.Before, jsonCoverage(v))
	}
	for _, v := range s.event.After {
		detail.After = append(detail.After, jsonCoverage(v))
	}
	for _, v := range s.event.Effects {
		coverage := jsonCoverage(v.Coverage)
		detail.Effects = append(detail.Effects, graphql2.ScheduleJSONCoverageChange{Coverage: &coverage, Change: v.Change, Source: v.Source})
	}
	out := &graphql2.UpdateDeletionPreview{Operation: graphql2.DeletionOperationSetTemporarySchedule, Root: safeUpdateResource(s.root), ImpactVersion: version, PolicyVersion: ds.PolicyVersion, Complete: true, CanProceed: true, RequiresConfirmation: schedulejsonguard.Destructive(s.event.Effects), Removed: []graphql2.DeletionResource{}, Impacts: []graphql2.DeletionImpact{}, ScheduleJSONUpdate: detail}
	if s.event.Operation == audit.Clear {
		out.Operation = graphql2.DeletionOperationClearTemporarySchedules
	}
	if out.RequiresConfirmation {
		out.CanProceed = s.plan.CanProceed()
		for _, v := range s.plan.Impacts() {
			out.Impacts = append(out.Impacts, graphql2.DeletionImpact{EdgeID: v.EdgeID, Target: safeUpdateResource(v.Target), ReferencingResource: safeUpdateResource(v.Referencing), Relation: previewRelationshipNames[v.Relationship], Change: previewChangeNames[v.Change], Policy: graphql2.DeletionPolicyWarning, Impact: "Temporary schedule or user shift time coverage is reduced; the Schedule and User remain present. Exact half-open intervals are in scheduleJSONUpdate.", RequiredAction: previewActionNames[v.RequiredAction], CanModifyReference: true})
		}
	}
	return out
}

func (q *Query) previewScheduleJSON(ctx context.Context, raw any) (*graphql2.UpdateDeletionPreview, error) {
	id, u, _, err := scheduleJSONIntent(raw)
	if err != nil {
		return nil, err
	}
	if q.DB == nil || q.ScheduleStore == nil || q.PreviewSigner == nil || hasInheritedContextTx(ctx) {
		return nil, previewUnavailable()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := q.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, previewUnavailable()
	}
	defer func() { _ = tx.Rollback() }()
	at := time.Now()
	s, err := (*App)(q).assessScheduleJSON(ctx, tx, id, u, at, false)
	if err != nil {
		return nil, safePreviewError(err)
	}
	version, err := encodeScheduleJSONVersion(q.PreviewSigner, s.digest, at)
	if err != nil {
		return nil, err
	}
	if err := tx.Rollback(); err != nil {
		return nil, previewUnavailable()
	}
	return s.response(version), nil
}
func (q *Query) PreviewSetTemporarySchedule(ctx context.Context, input graphql2.SetTemporaryScheduleInput) (*graphql2.UpdateDeletionPreview, error) {
	return q.previewScheduleJSON(ctx, input)
}
func (q *Query) PreviewClearTemporarySchedules(ctx context.Context, input graphql2.ClearTemporarySchedulesInput) (*graphql2.UpdateDeletionPreview, error) {
	return q.previewScheduleJSON(ctx, input)
}

func (m *Mutation) executeScheduleJSON(ctx context.Context, raw any) (bool, error) {
	id, u, c, err := scheduleJSONIntent(raw)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err = withContextTx(ctx, m.DB, func(ctx context.Context, tx *sql.Tx) error {
		now := time.Now()
		at := now
		var version *scheduleJSONVersion
		if c != nil && c.ExpectedImpactVersion != "" {
			v, err := decodeScheduleJSONVersion(m.PreviewSigner, c.ExpectedImpactVersion, now)
			if err != nil {
				return err
			}
			version = &v
			at = time.Unix(0, v.At)
		}
		s, err := (*App)(m).assessScheduleJSON(ctx, tx, id, u, at, true)
		if err != nil {
			return err
		}
		if version != nil && version.Digest != s.digest {
			return &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
		}
		destructive := schedulejsonguard.Destructive(s.event.Effects)
		if destructive && (c == nil || !c.AcknowledgeImpacts || version == nil) {
			return &ds.DeletionSafetyError{Code: ds.DeletionConfirmationRequired}
		}
		if destructive {
			if err := s.plan.Check(s.plan.ImpactVersion(), true); err != nil {
				return err
			}
		}
		if version != nil {
			actual, err := (*App)(m).assessScheduleJSON(ctx, tx, id, u, time.Now(), true)
			if err != nil {
				return err
			}
			if !scheduleJSONAttenuates(s.event.Effects, actual.event.Effects) {
				return &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
			}
			s = actual
		}
		guarded, err := schedulejsonguard.Bind(ctx, tx, s.event)
		if err != nil {
			return err
		}
		org := s.event.OrganizationID
		return m.ScheduleStore.ExecuteTemporaryUpdate(guarded, tx, id, &org, s.update)
	})
	if err != nil {
		return false, scheduleTargetUpdateSafeError(err)
	}
	return true, nil
}
