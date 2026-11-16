package postgres

import (
	"context"
	"database/sql"
	"slices"
	"time"

	ds "github.com/target/goalert/deletionsafety"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/validation/validate"
)

// Selector preserves the legacy DeleteAll selection. IntegrationKey uses its
// legacy credential selector ONLY as a SQL predicate, never as a plan identity.
// Do not log or serialize selectors.
type Selector = guard.Selector

// Enforce joins the existing READ COMMITTED transaction. It never begins,
// commits, rolls back, writes audit, or expands the explicit selection. The
// authorizer is trusted server code, identical to Preview's operation admission.
// A guard is issued only after complete fresh facts and the accepted BuildPlan.
func Enforce(ctx context.Context, tx *sql.Tx, raw []Selector, expected string, acknowledged bool, authorize AuthorizeFacts) (context.Context, error) {
	if ctx == nil || tx == nil || authorize == nil {
		return ctx, unavailable()
	}
	if len(raw) == 0 {
		return ctx, nil
	}
	// Validate RAW counts and UUIDs before normalization/deduplication.
	groups := map[ds.ResourceKind][]string{}
	for _, s := range raw {
		if _, ok := identityQueries[s.Kind]; !ok {
			return ctx, unavailable()
		}
		groups[s.Kind] = append(groups[s.Kind], s.ID)
	}
	for _, kind := range []ds.ResourceKind{ds.ResourceRotation, ds.ResourceUserOverride, ds.ResourceSchedule, ds.ResourceUser, ds.ResourceIntegrationKey, ds.ResourceService, ds.ResourceEscalationPolicy, ds.ResourceNotificationRule, ds.ResourceContactMethod} {
		ids := groups[kind]
		if len(ids) == 0 {
			continue
		}
		limit := 50
		if kind == ds.ResourceUser {
			limit = 100
		}
		if _, err := validate.ParseManyUUID(map[ds.ResourceKind]string{ds.ResourceService: "ServiceID", ds.ResourceEscalationPolicy: "EscalationPolicyID", ds.ResourceSchedule: "ScheduleID", ds.ResourceRotation: "RotationID", ds.ResourceUser: "UserID", ds.ResourceContactMethod: "ContactMethodID", ds.ResourceNotificationRule: "NotificationRuleID", ds.ResourceIntegrationKey: "IntegrationKeyID", ds.ResourceUserOverride: "UserOverrideID"}[kind], ids, limit); err != nil {
			return ctx, err
		}
	}
	if len(raw) > ds.DefaultBudget().MaxTargets {
		return ctx, limitExceeded()
	}
	var isolation, readOnly string
	if err := tx.QueryRowContext(ctx, `SELECT current_setting('transaction_isolation'),current_setting('transaction_read_only')`).Scan(&isolation, &readOnly); err != nil {
		return ctx, safeError(err)
	}
	if isolation != "read committed" || readOnly != "off" {
		return ctx, unavailable()
	}
	// Only homogeneous NR, CM, Service or EP profiles are executable. Raw validation keeps existing
	// error precedence and counts; no unsupported root reaches business DML.
	if len(groups) != 1 || (len(groups[ds.ResourceNotificationRule]) == 0 && len(groups[ds.ResourceContactMethod]) == 0 && len(groups[ds.ResourceService]) == 0 && len(groups[ds.ResourceEscalationPolicy]) == 0) {
		return ctx, unavailable()
	}
	collectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	stabilize := guard.StabilizeNR
	if len(groups[ds.ResourceContactMethod]) > 0 {
		stabilize = guard.StabilizeCM
	}
	if len(groups[ds.ResourceService]) > 0 {
		stabilize = guard.StabilizeService
	}
	if len(groups[ds.ResourceEscalationPolicy]) > 0 {
		stabilize = guard.StabilizeEP
	}
	stableCtx, targets, err := stabilize(collectCtx, tx, raw)
	if err != nil {
		return ctx, safeError(err)
	}
	collectCtx = stableCtx
	collection := ds.Collection{Completeness: ds.DependenciesComplete}
	remaining := ds.DefaultBudget().MaxDependencies
	var fingerprint string
	for _, root := range targets {
		limits := DefaultLimits()
		limits.MaxRows = max(1, remaining)
		result, err := Collect(collectCtx, tx, root, Recheck, limits, authorize)
		if err != nil {
			return ctx, safeError(err)
		}
		if result.Collection.Completeness != ds.DependenciesComplete || !slices.Contains(result.Collection.Checked, root) || fingerprint != "" && fingerprint != result.ScopeFingerprint {
			return ctx, unavailable()
		}
		fingerprint = result.ScopeFingerprint
		collection.Checked = append(collection.Checked, result.Collection.Checked...)
		collection.Dependencies = append(collection.Dependencies, result.Collection.Dependencies...)
		for _, d := range result.Collection.Dependencies {
			remaining -= 1 + len(d.Before.References) + len(d.After.References)
		}
		if remaining < 0 {
			return ctx, limitExceeded()
		}
	}
	if len(targets) == 0 && expected != "" {
		return ctx, &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
	}
	var plan ds.DeletionPlan
	if len(targets) > 0 {
		intent := make([]ds.DestructiveChange, len(targets))
		for i, r := range targets {
			intent[i] = ds.DestructiveChange{Resource: r, Kind: ds.ChangeDeleted}
		}
		var err error
		plan, err = ds.BuildPlan(ds.PlanInput{Operation: ds.OperationDeleteResources, Targets: targets, Intent: intent, Collection: collection, ScopeFingerprint: fingerprint}, ds.Budget{})
		if err != nil {
			return ctx, safeError(err)
		}
		// Confirmation cannot override a BLOCK.
		if !plan.CanProceed() {
			return ctx, plan.Check(expected, acknowledged)
		}
		if err := plan.Check(expected, acknowledged); err != nil {
			return ctx, err
		}
	}
	return guard.Bind(ctx, tx, collectCtx, raw, plan, expected, acknowledged)
}
