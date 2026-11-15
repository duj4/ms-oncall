package graphqlapp

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/google/uuid"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/graphql2"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func previewUnavailable() error { return &ds.DeletionSafetyError{Code: ds.DeletionUnavailable} }
func previewLimit() error       { return &ds.DeletionSafetyError{Code: ds.DeletionPreviewLimitExceeded} }

// This boundary never forwards SQL, authorization diagnostics or partial facts.
// It is deliberately scoped to the new Query; existing deletes are unchanged.
func deletionPreviewGraphQLError(ctx context.Context, err error) *gqlerror.Error {
	code := ds.DeletionUnavailable
	var typed *ds.DeletionSafetyError
	if errors.As(err, &typed) {
		switch typed.Code {
		case ds.DeletionBlocked, ds.DeletionConfirmationRequired, ds.DeletionDependencyChanged, ds.DeletionUnavailable, ds.DeletionPreviewLimitExceeded:
			code = typed.Code
		}
	}
	safe := &ds.DeletionSafetyError{Code: code}
	return &gqlerror.Error{Message: safe.Error(), Path: graphql.GetPath(ctx), Extensions: map[string]any{"code": graphql2.ErrorCode(code)}}
}

var previewTargetKinds = map[graphql2.DeletionTargetType]ds.ResourceKind{
	graphql2.DeletionTargetTypeService:          ds.ResourceService,
	graphql2.DeletionTargetTypeEscalationPolicy: ds.ResourceEscalationPolicy,
	graphql2.DeletionTargetTypeSchedule:         ds.ResourceSchedule,
	graphql2.DeletionTargetTypeRotation:         ds.ResourceRotation,
	graphql2.DeletionTargetTypeUser:             ds.ResourceUser,
	graphql2.DeletionTargetTypeContactMethod:    ds.ResourceContactMethod,
	graphql2.DeletionTargetTypeNotificationRule: ds.ResourceNotificationRule,
	graphql2.DeletionTargetTypeIntegrationKey:   ds.ResourceIntegrationKey,
	graphql2.DeletionTargetTypeUserOverride:     ds.ResourceUserOverride,
}

func previewTargets(input graphql2.DeletionPlanInput, first *int) ([]ds.Resource, int, error) {
	// No destructive-diff adapters exist yet for any of the eight update families.
	if input.Operation != graphql2.DeletionOperationDeleteResources {
		return nil, 0, previewUnavailable()
	}
	pageSize := 50
	if first != nil {
		pageSize = *first
	}
	if pageSize < 1 || pageSize > 100 || len(input.Targets) == 0 {
		return nil, 0, previewUnavailable()
	}
	if len(input.Targets) > ds.DefaultBudget().MaxTargets {
		return nil, 0, previewLimit()
	}
	targets := make([]ds.Resource, 0, len(input.Targets))
	seen := map[ds.Resource]bool{}
	counts := map[ds.ResourceKind]int{}
	for _, raw := range input.Targets {
		kind, ok := previewTargetKinds[raw.Type]
		id, err := uuid.Parse(raw.ID)
		if !ok || err != nil || id == uuid.Nil || id.String() != raw.ID {
			return nil, 0, previewUnavailable()
		}
		obj := ds.Resource{Kind: kind, ID: id.String()}
		if seen[obj] {
			return nil, 0, previewUnavailable()
		}
		seen[obj] = true
		counts[kind]++
		// Preserve the existing mutation-family raw selection bounds.
		if kind != ds.ResourceUser && counts[kind] > 50 {
			return nil, 0, previewLimit()
		}
		targets = append(targets, obj)
	}
	slices.SortFunc(targets, func(a, b ds.Resource) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return comparePreviewString(a.ID, b.ID)
	})
	return targets, pageSize, nil
}

func comparePreviewString(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// DeletionPreview owns one disposable snapshot. It never joins a mutation's
// transaction, invokes a Store or captures a successful audit/event identity.
func (q *Query) DeletionPreview(ctx context.Context, input graphql2.DeletionPlanInput, first *int, after *string) (_ *graphql2.DeletionPreview, err error) {
	targets, pageSize, err := previewTargets(input, first)
	if err != nil {
		return nil, err
	}
	authority, err := newPreviewAuthority(ctx)
	if err != nil || q.DB == nil || q.PreviewSigner == nil || hasInheritedContextTx(ctx) {
		return nil, previewUnavailable()
	}
	// Bound the whole batch, not one 15-second window for each selected root.
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var cursor *deletionPreviewCursor
	if after != nil {
		cursor, err = decodeDeletionPreviewCursor(q.PreviewSigner, *after)
		if err != nil {
			return nil, previewUnavailable()
		}
	}
	tx, err := q.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, safePreviewError(err)
	}
	defer func() { _ = tx.Rollback() }()
	collection := ds.Collection{Completeness: ds.DependenciesComplete}
	var fingerprint string
	var assessedAt time.Time
	remaining := ds.DefaultBudget().MaxDependencies
	rootFacts := make(map[ds.Resource]collector.Target)
	for _, root := range targets {
		limits := collector.DefaultLimits()
		limits.MaxRows = max(1, remaining)
		result, collectErr := collector.Collect(ctx, tx, root, collector.Preview, limits, func(ctx context.Context, tx *sql.Tx, facts collector.Target) error {
			if err := authority.authorizeTarget(ctx, tx, facts); err != nil {
				return err
			}
			rootFacts[facts.Resource()] = facts
			return nil
		})
		if collectErr != nil {
			return nil, safePreviewError(collectErr)
		}
		if result.Collection.Completeness != ds.DependenciesComplete || !slices.Contains(result.Collection.Checked, root) {
			return nil, previewUnavailable()
		}
		if fingerprint != "" && fingerprint != result.ScopeFingerprint {
			return nil, previewUnavailable()
		}
		fingerprint = result.ScopeFingerprint
		if assessedAt.IsZero() {
			assessedAt = result.ObservedAt
		}
		collection.Checked = append(collection.Checked, result.Collection.Checked...)
		collection.Dependencies = append(collection.Dependencies, result.Collection.Dependencies...)
		for _, d := range result.Collection.Dependencies {
			remaining -= 1 + len(d.Before.References) + len(d.After.References)
		}
		if remaining < 0 {
			return nil, previewLimit()
		}
	}
	intent := make([]ds.DestructiveChange, len(targets))
	for i, target := range targets {
		intent[i] = ds.DestructiveChange{Resource: target, Kind: ds.ChangeDeleted}
	}
	plan, err := ds.BuildPlan(ds.PlanInput{Operation: ds.OperationDeleteResources, Targets: targets, Intent: intent, Collection: collection, ScopeFingerprint: fingerprint}, ds.Budget{})
	if err != nil {
		return nil, safePreviewError(err)
	}
	// Authorization includes dependencies outside the display page. A hidden or
	// unauthorized reference never turns into a count or an executable partial plan.
	impacts := plan.Impacts()
	owners := previewReferenceOwners(collection, rootFacts)
	for _, impact := range impacts {
		if !authority.canReadImpact(impact, owners) {
			return nil, previewUnavailable()
		}
	}
	binding := newDeletionPreviewCursor(targets, fingerprint, plan.ImpactVersion())
	if cursor != nil {
		if cursor.Operation != binding.Operation || cursor.Selection != binding.Selection || cursor.Scope != binding.Scope {
			return nil, previewUnavailable()
		}
		if cursor.Policy != binding.Policy || cursor.Impact != binding.Impact {
			return nil, &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
		}
	}
	start := 0
	if cursor != nil {
		at, found := slices.BinarySearchFunc(impacts, cursor.Position, func(d ds.DeletionImpact, s string) int { return comparePreviewString(d.EdgeID, s) })
		if !found {
			return nil, previewUnavailable()
		}
		start = at + 1
	}
	end := min(start+pageSize, len(impacts))
	response, err := projectDeletionPreview(ctx, tx, authority, plan, impacts[start:end], binding, rootFacts, q.PreviewSigner)
	if err != nil {
		return nil, safePreviewError(err)
	}
	response.AssessedAt = assessedAt
	response.Impacts.PageInfo.HasNextPage = end < len(impacts)
	// End the transaction before publishing any response, including empty pages.
	if err := tx.Rollback(); err != nil {
		return nil, previewUnavailable()
	}
	return response, nil
}

func safePreviewError(err error) error {
	var typed *ds.DeletionSafetyError
	if errors.As(err, &typed) {
		return &ds.DeletionSafetyError{Code: typed.Code}
	}
	return previewUnavailable()
}
