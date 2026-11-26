package graphqlapp

import (
	"context"
	"database/sql"
	"reflect"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/graphql2"
)

// All inputs to this projector came from complete, authorized Collector facts.
// The catalog fetches only public display names, with no business Store/getter,
// destination, alert summary, provider identity or credential selector access.
var previewNameQueries = map[ds.ResourceKind]string{
	ds.ResourceService:          `SELECT id::text,name FROM services WHERE id=ANY($1::uuid[])`,
	ds.ResourceEscalationPolicy: `SELECT id::text,name FROM escalation_policies WHERE id=ANY($1::uuid[])`,
	ds.ResourceSchedule:         `SELECT id::text,name FROM schedules WHERE id=ANY($1::uuid[])`,
	ds.ResourceRotation:         `SELECT id::text,name FROM rotations WHERE id=ANY($1::uuid[])`,
	ds.ResourceUser:             `SELECT id::text,name FROM users WHERE id=ANY($1::uuid[])`,
	ds.ResourceContactMethod:    `SELECT id::text,name FROM user_contact_methods WHERE id=ANY($1::uuid[])`,
	ds.ResourceIntegrationKey:   `SELECT audit_resource_id::text,name FROM integration_keys WHERE audit_resource_id=ANY($1::uuid[])`,
}

func projectDeletionPreview(ctx context.Context, tx *sql.Tx, a previewAuthority, plan ds.DeletionPlan, page []ds.DeletionImpact, binding deletionPreviewCursor, facts map[ds.Resource]collector.Target, signer DeletionCursorSigner) (*graphql2.DeletionPreview, error) {
	resources := map[ds.Resource]*graphql2.DeletionResource{}
	add := func(r ds.Resource, optional bool) error {
		if optional && r == (ds.Resource{}) {
			return nil
		}
		name := previewResourceNames[r.Kind]
		if name == "" || len(r.ID) == 0 || len(r.ID) > 256 || strings.ContainsFunc(r.ID, func(c rune) bool {
			return (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune("-_:./", c)
		}) {
			return previewUnavailable()
		}
		resources[r] = &graphql2.DeletionResource{ID: r.ID, Type: name, Label: name + " " + r.ID}
		return nil
	}
	for _, r := range plan.Targets() {
		if err := add(r, false); err != nil {
			return nil, err
		}
	}
	impacts := plan.Impacts()
	for _, d := range page {
		// The immutable planner is the authority for causal and ownership facts.
		// A page must contain exact plan rows, even when its direct cause is on
		// another page. Do not infer ancestors or recompute policy/edge identities.
		at, found := slices.BinarySearchFunc(impacts, d.EdgeID, func(d ds.DeletionImpact, id string) int { return comparePreviewString(d.EdgeID, id) })
		if !found || !reflect.DeepEqual(d, impacts[at]) {
			return nil, previewUnavailable()
		}
		for _, r := range []ds.Resource{d.Target, d.Referencing, d.Affected} {
			if err := add(r, false); err != nil {
				return nil, err
			}
		}
		for _, r := range []ds.Resource{d.Parent, d.Owner} {
			if err := add(r, true); err != nil {
				return nil, err
			}
		}
	}
	grouped := map[ds.ResourceKind][]string{}
	for r := range resources {
		if previewNameQueries[r.Kind] != "" {
			grouped[r.Kind] = append(grouped[r.Kind], r.ID)
		}
	}
	for kind, ids := range grouped {
		slices.Sort(ids)
		rows, err := tx.QueryContext(ctx, previewNameQueries[kind], pq.Array(ids))
		if err != nil {
			return nil, previewUnavailable()
		}
		count := 0
		for rows.Next() {
			var id, name string
			if err := rows.Scan(&id, &name); err != nil {
				_ = rows.Close()
				return nil, previewUnavailable()
			}
			r, ok := resources[ds.Resource{Kind: kind, ID: id}]
			if !ok || r.Name != nil {
				_ = rows.Close()
				return nil, previewUnavailable()
			}
			r.Name = &name
			r.Label = name
			count++
		}
		scanErr := rows.Err()
		closeErr := rows.Close()
		if scanErr != nil || closeErr != nil || count != len(ids) {
			return nil, previewUnavailable()
		}
	}
	organizations := map[uuid.UUID]*graphql2.DeletionOrganizationSummary{}
	for r, t := range facts {
		if resources[r] == nil {
			return nil, previewUnavailable()
		}
		org := t.OrganizationID()
		summary := organizations[org]
		if summary == nil {
			var name string
			if err := tx.QueryRowContext(ctx, `SELECT display_name FROM organizations WHERE id=$1`, org).Scan(&name); err != nil {
				return nil, previewUnavailable()
			}
			summary = &graphql2.DeletionOrganizationSummary{ID: org.String(), Name: name}
			organizations[org] = summary
		}
		resources[r].Organization = summary
	}
	if !a.system {
		// Collector proved every reference belongs to the same Normal Home.
		summary := organizations[a.home]
		for _, r := range resources {
			r.Organization = summary
		}
	}
	response := &graphql2.DeletionPreview{
		Operation: graphql2.DeletionOperationDeleteResources, ImpactVersion: plan.ImpactVersion(), PolicyVersion: ds.PolicyVersion,
		Complete: true, CanProceed: plan.CanProceed(), RequiresConfirmation: plan.CanProceed() && plan.RequiresConfirmation(),
		Targets: []graphql2.DeletionResource{}, Notices: []string{"Preview is a snapshot. Deletion must reauthorize and recheck dependencies in its owning transaction."},
		Impacts: &graphql2.DeletionImpactConnection{Edges: []graphql2.DeletionImpactEdge{}, PageInfo: &graphql2.PageInfo{}},
	}
	for _, r := range plan.Targets() {
		response.Targets = append(response.Targets, *resources[r])
	}
	policies := map[ds.DeletionPolicy]graphql2.DeletionPolicy{ds.PolicyBlock: graphql2.DeletionPolicyBlock, ds.PolicyCascade: graphql2.DeletionPolicyCascade, ds.PolicyWarning: graphql2.DeletionPolicyWarning, ds.PolicyInformational: graphql2.DeletionPolicyInformational}
	for _, d := range page {
		binding.Position = d.EdgeID
		cursor, err := encodeDeletionPreviewCursor(signer, binding)
		if err != nil {
			return nil, err
		}
		node := &graphql2.DeletionImpact{EdgeID: d.EdgeID, Target: resources[d.Target], ReferencingResource: resources[d.Referencing], Parent: resources[d.Parent], Relation: previewRelationshipNames[d.Relationship], Change: previewChangeNames[d.Change], Policy: policies[d.Policy], Impact: deletionImpactDescription(d), RequiredAction: previewActionNames[d.RequiredAction], CanModifyReference: a.canModify(d.Referencing, d.Owner), IsDerived: d.IsDerived, IsPlannedCoDeletion: d.IsPlannedCoDeletion}
		node.Owner = resources[d.Owner]
		node.AffectedResource = resources[d.Affected]
		if d.IsDerived {
			if d.DerivedFrom == "" {
				return nil, previewUnavailable()
			}
			node.DerivedFrom = &d.DerivedFrom
		} else if d.DerivedFrom != "" {
			return nil, previewUnavailable()
		}
		if node.Target == nil || node.ReferencingResource == nil || node.AffectedResource == nil || node.Relation == "" || node.Change == "" || node.Policy == "" || node.RequiredAction == "" {
			return nil, previewUnavailable()
		}
		response.Impacts.Edges = append(response.Impacts.Edges, graphql2.DeletionImpactEdge{Cursor: cursor, Node: node})
		response.Impacts.PageInfo.EndCursor = &cursor
	}
	return response, nil
}

func deletionImpactDescription(d ds.DeletionImpact) string {
	if d.Policy == ds.PolicyBlock {
		return "Resolve the blocking dependency before deletion."
	}
	switch d.Change {
	case ds.ChangeDeleted:
		return "The affected resource would be deleted."
	case ds.ChangeRelationRemoved:
		return "The affected relationship would be removed."
	case ds.ChangeRelationReplaced:
		return "The affected relationship would be replaced."
	case ds.ChangeConfigTrimmed:
		return "The affected configuration would be reduced."
	case ds.ChangePreserved:
		return "The affected resource is preserved."
	default:
		return "Review the configuration impact before deletion."
	}
}
