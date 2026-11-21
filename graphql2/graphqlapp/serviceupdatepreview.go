package graphqlapp

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/internal/servicepolicy"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/service"
	"github.com/target/goalert/validation/validate"
)

type serviceUpdateAssessment struct {
	updateAssessment
	facts servicepolicy.Facts
}

func serviceUpdateFields(svc *service.Service, input graphql2.UpdateServiceInput) {
	if input.Name != nil {
		svc.Name = *input.Name
	}
	if input.Description != nil {
		svc.Description = *input.Description
	}
	if input.EscalationPolicyID != nil {
		svc.EscalationPolicyID = *input.EscalationPolicyID
	}
	if input.MaintenanceExpiresAt != nil {
		svc.MaintenanceExpiresAt = *input.MaintenanceExpiresAt
	}
}

func (a *App) assessServiceUpdate(ctx context.Context, tx *sql.Tx, input graphql2.UpdateServiceInput, locked bool) (serviceUpdateAssessment, error) {
	s := serviceUpdateAssessment{updateAssessment: updateAssessment{operation: ds.OperationUpdateService, root: updateObject(ds.ResourceService, input.ID)}}
	home, err := serviceManagementAuthority(ctx, serviceManagementUpdate)
	if err != nil {
		return s, previewUnavailable()
	}
	if err := validate.UUID("ServiceID", input.ID); err != nil {
		return s, err
	}
	org := home
	if ec := executioncontext.ExecutionContextFromContext(ctx); ec != nil && ec.Privileges().PlatformAdmin() {
		org = nil
	}
	// Preserve original field validation and missing/null semantics before
	// loading private routing facts. No alternate update implementation.
	var svc service.Service
	var maintenance sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT id,organization_id,name,description,escalation_policy_id,maintenance_expires_at FROM services WHERE id=$1 AND ($2::uuid IS NULL OR organization_id=$2)`, input.ID, org).Scan(&svc.ID, &svc.OrganizationID, &svc.Name, &svc.Description, &svc.EscalationPolicyID, &maintenance)
	if err != nil {
		return s, safePreviewError(err)
	}
	svc.MaintenanceExpiresAt = maintenance.Time
	serviceUpdateFields(&svc, input)
	desired, err := svc.Normalize()
	if err != nil {
		return s, err
	}
	s.facts, err = servicepolicy.Load(ctx, tx, input.ID, input.EscalationPolicyID, org, locked)
	if err != nil {
		return s, safePreviewError(err)
	}
	s.root.ID = s.facts.Service.String()
	desired.EscalationPolicyID = s.facts.After.String()
	scope, err := collector.UpdateScope(ctx, tx, s.facts.Organization, locked)
	if err != nil {
		return s, err
	}
	if s.facts.Changed() {
		old := updateObject(ds.ResourceEscalationPolicy, s.facts.Before.String())
		next := updateObject(ds.ResourceEscalationPolicy, s.facts.After.String())
		state := ds.AlertClosed
		var references []ds.Resource
		for _, alert := range s.facts.Alerts {
			if alert.Status == "closed" {
				continue
			}
			if state == ds.AlertClosed {
				state = ds.AlertTriggered
			}
			if alert.Status == "active" {
				state = ds.AlertActive
			}
			references = append(references, updateObject(ds.ResourceAlert, strconv.FormatInt(alert.ID, 10)))
		}
		// One actual FK relationship, with the entire affected open-Alert set.
		dependencies := []ds.Dependency{{Target: s.root, Referencing: old, Relationship: ds.RelationshipChangedServicePolicy, State: ds.BusinessState{Alert: state}, Before: ds.Configuration{References: references}}}
		s.plan, err = ds.BuildPlan(ds.PlanInput{Operation: s.operation, Targets: []ds.Resource{s.root}, Intent: []ds.DestructiveChange{{Resource: s.root, Kind: ds.ChangeRelationReplaced, Before: ds.Configuration{References: []ds.Resource{old}}, After: ds.Configuration{References: []ds.Resource{next}}}}, Collection: ds.Collection{Completeness: ds.DependenciesComplete, Checked: []ds.Resource{s.root}, Dependencies: dependencies}, ScopeFingerprint: scope}, ds.Budget{})
		if err != nil {
			return s, err
		}
		// No Root/child is deleted. The frozen A1 service.update requested-field
		// audit is the approved contract for this FK and runtime UPDATE.
		for _, change := range s.plan.Changes() {
			if change.Resource != s.root || change.Kind != ds.ChangeRelationReplaced {
				return s, previewUnavailable()
			}
		}
	}
	input.Confirmation = nil
	input.ID = s.facts.Service.String()
	if input.EscalationPolicyID != nil {
		next := s.facts.After.String()
		input.EscalationPolicyID = &next
	}
	factsDigest, err := s.facts.Digest()
	if err != nil {
		return s, err
	}
	manifest, err := json.Marshal([]any{ds.PolicyVersion, scope, input, desired, factsDigest, s.plan.ImpactVersion()})
	if err != nil {
		return s, previewUnavailable()
	}
	s.digest = hexDigest(manifest)
	return s, nil
}

func (s serviceUpdateAssessment) enforceService(ctx context.Context, tx *sql.Tx, signer DeletionCursorSigner, c *graphql2.DeletionSafetyConfirmationInput) (context.Context, error) {
	if s.facts.RequiresConfirmation() {
		if c == nil || !c.AcknowledgeImpacts || c.ExpectedImpactVersion == "" {
			return ctx, &ds.DeletionSafetyError{Code: ds.DeletionConfirmationRequired}
		}
		if err := s.plan.Check(s.plan.ImpactVersion(), true); err != nil {
			return ctx, err
		}
	}
	// Shared Update signer/domain verification; removed stays empty because
	// this operation never obtains child/root deletion capabilities.
	ctx, err := s.enforce(ctx, tx, signer, c)
	if err != nil {
		return ctx, err
	}
	if s.facts.RequiresConfirmation() {
		return servicepolicy.Bind(ctx, tx, s.facts)
	}
	return ctx, nil
}

func (q *Query) PreviewUpdateService(ctx context.Context, input graphql2.UpdateServiceInput) (_ *graphql2.UpdateDeletionPreview, err error) {
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
	s, err := (*App)(q).assessServiceUpdate(ctx, tx, input, false)
	if err != nil {
		return nil, safePreviewError(err)
	}
	sig, err := q.PreviewSigner.Sign([]byte(updateVersionDomain + s.digest))
	if err != nil {
		return nil, previewUnavailable()
	}
	response := &graphql2.UpdateDeletionPreview{Operation: graphql2.DeletionOperationUpdateService, Root: safeUpdateResource(s.root), PolicyVersion: ds.PolicyVersion, Complete: true, CanProceed: true, RequiresConfirmation: s.facts.RequiresConfirmation(), ImpactVersion: s.digest + "." + base64.RawURLEncoding.EncodeToString(sig), Removed: []graphql2.DeletionResource{}, Impacts: []graphql2.DeletionImpact{}}
	authority := previewAuthority{ctx: ctx, system: permission.System(ctx)}
	openAlerts := 0
	for _, alert := range s.facts.Alerts {
		if alert.Status != "closed" {
			openAlerts++
		}
	}
	description := fmt.Sprintf("The Service and both policies are preserved. Replacing this policy reference resets %d existing escalation states for %d open alerts.", len(s.facts.States), openAlerts)
	for _, d := range s.plan.Impacts() {
		policy := graphql2.DeletionPolicyInformational
		if d.Policy == ds.PolicyWarning {
			policy = graphql2.DeletionPolicyWarning
		}
		response.Impacts = append(response.Impacts, graphql2.DeletionImpact{EdgeID: d.EdgeID, Target: safeUpdateResource(d.Target), ReferencingResource: safeUpdateResource(d.Referencing), Relation: previewRelationshipNames[d.Relationship], Change: previewChangeNames[d.Change], Policy: policy, Impact: description, RequiredAction: previewActionNames[d.RequiredAction], CanModifyReference: authority.canModify(d.Referencing, d.Owner)})
	}
	if err := tx.Rollback(); err != nil {
		return nil, previewUnavailable()
	}
	return response, nil
}
