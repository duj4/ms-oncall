package graphqlapp

import (
	"context"
	"database/sql"
	"errors"

	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/graphql2"
)

// The generated GraphQL signature adds one optional argument. The existing Go
// entry stays source-compatible and enters the SAME protected implementation.
type deletionMutationResolver struct{ *Mutation }

func (a deletionMutationResolver) DeleteAll(ctx context.Context, input []assignment.RawTarget, confirmation *graphql2.DeletionSafetyConfirmationInput) (bool, error) {
	return a.deleteAllConfirmed(ctx, input, confirmation)
}

var deleteTargetKinds = map[assignment.TargetType]ds.ResourceKind{
	assignment.TargetTypeService:          ds.ResourceService,
	assignment.TargetTypeEscalationPolicy: ds.ResourceEscalationPolicy,
	assignment.TargetTypeSchedule:         ds.ResourceSchedule,
	assignment.TargetTypeRotation:         ds.ResourceRotation,
	assignment.TargetTypeUser:             ds.ResourceUser,
	assignment.TargetTypeContactMethod:    ds.ResourceContactMethod,
	assignment.TargetTypeNotificationRule: ds.ResourceNotificationRule,
	assignment.TargetTypeIntegrationKey:   ds.ResourceIntegrationKey,
	assignment.TargetTypeUserOverride:     ds.ResourceUserOverride,
}

func enforceDeleteAll(ctx context.Context, tx *sql.Tx, input []assignment.RawTarget, confirmation *graphql2.DeletionSafetyConfirmationInput) (context.Context, error) {
	var selectors []collector.Selector
	for _, raw := range input {
		if raw.TargetType() == assignment.TargetTypeUserSession {
			continue
		} // existing revoke contract
		kind, ok := deleteTargetKinds[raw.TargetType()]
		if !ok {
			return ctx, previewUnavailable()
		}
		selectors = append(selectors, collector.Selector{Kind: kind, ID: raw.TargetID()})
	}
	if len(selectors) == 0 {
		return ctx, nil
	}
	authority, err := newPreviewAuthority(ctx)
	if err != nil {
		return ctx, err
	}
	expected := ""
	acknowledged := false
	if confirmation != nil {
		expected = confirmation.ExpectedImpactVersion
		acknowledged = confirmation.AcknowledgeImpacts
	}
	return collector.Enforce(ctx, tx, selectors, expected, acknowledged, authority.authorizeTarget)
}

func deletionSafetyError(err error) (*ds.DeletionSafetyError, bool) {
	var typed *ds.DeletionSafetyError
	if errors.As(err, &typed) {
		return &ds.DeletionSafetyError{Code: typed.Code}, true
	}
	return nil, false
}
