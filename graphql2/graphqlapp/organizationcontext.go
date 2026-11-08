package graphqlapp

import (
	"context"

	"github.com/google/uuid"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/escalation"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/schedule/rotation"
	"github.com/target/goalert/search"
	"github.com/target/goalert/service"
	"github.com/target/goalert/validation/validate"
)

func (q *Query) CurrentOrganizationContext(ctx context.Context) (*graphql2.CurrentOrganizationContext, error) {
	ec, err := executioncontext.CheckHumanAuthority(ctx)
	if err != nil {
		return nil, err
	}
	home, _ := ec.HomeOrganizationID()
	org, err := organization.NewStore(q.DB).FindByID(ctx, home)
	if err != nil {
		return nil, err
	}
	pa := ec.Privileges().PlatformAdmin()
	return &graphql2.CurrentOrganizationContext{
		UserID: ec.ActualActorID(), HomeOrganization: &graphql2.OrganizationSummary{ID: org.ID.String(), DisplayName: org.DisplayName},
		HomeClassification: string(org.Classification), HomeOrgRole: string(ec.Privileges().OrganizationRole()),
		IsPlatformAdmin: pa, CanManageOrganizations: pa, CanReadGlobalRoots: pa,
		CanCreateGlobalRoots: pa,
	}, nil
}

type organizationDirectoryCursor struct{ Name, ID, Search string }

func (q *Query) ManageableOrganizations(ctx context.Context, first *int, after, filter *string) (*graphql2.OrganizationDirectoryConnection, error) {
	ec, err := executioncontext.CheckHumanAuthority(ctx)
	if err != nil {
		return nil, err
	}
	if !ec.Privileges().PlatformAdmin() {
		return nil, permission.NewAccessDenied("PlatformAdmin authority is required")
	}
	n := 25
	if first != nil {
		n = *first
	}
	if err := validate.Range("first", n, 1, 100); err != nil {
		return nil, err
	}
	var c organizationDirectoryCursor
	if filter != nil {
		c.Search = *filter
	}
	if after != nil && *after != "" {
		var previous organizationDirectoryCursor
		if err := search.ParseCursor(*after, &previous); err != nil {
			return nil, err
		}
		if previous.Search != c.Search {
			return nil, permission.NewAccessDenied("cursor search does not match")
		}
		c = previous
	}
	rows, err := q.DB.QueryContext(ctx, `SELECT o.id,o.display_name FROM organizations o
	 JOIN normal_organizations n ON n.organization_id=o.id AND n.organization_classification=o.classification
	 WHERE o.classification='NORMAL' AND o.id<>$1 AND o.id<>$2
	 AND (o.display_name,o.id::text)>($3,$4)
	 AND strpos(lower(o.display_name),lower($5))>0
	 ORDER BY o.display_name,o.id::text LIMIT $6`, organization.DefaultOrganizationID, uuid.Nil, c.Name, c.ID, c.Search, n+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	conn := &graphql2.OrganizationDirectoryConnection{Nodes: []graphql2.OrganizationSummary{}, PageInfo: &graphql2.PageInfo{}}
	for rows.Next() {
		var node graphql2.OrganizationSummary
		if err := rows.Scan(&node.ID, &node.DisplayName); err != nil {
			return nil, err
		}
		conn.Nodes = append(conn.Nodes, node)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(conn.Nodes) > n {
		conn.PageInfo.HasNextPage = true
		conn.Nodes = conn.Nodes[:n]
	}
	if len(conn.Nodes) > 0 {
		last := conn.Nodes[len(conn.Nodes)-1]
		c.Name = last.DisplayName
		c.ID = last.ID
		cursor, err := search.Cursor(c)
		if err != nil {
			return nil, err
		}
		conn.PageInfo.EndCursor = &cursor
	}
	return conn, nil
}

func (a *App) rootOrganizationSummary(ctx context.Context, typ assignment.TargetType, id string) (*graphql2.OrganizationSummary, error) {
	scope, err := a.rootReadScope(ctx, typ, id)
	if err != nil {
		return nil, err
	}
	actual, err := a.normalRootTarget(ctx, typ, id)
	if err != nil {
		return nil, err
	}
	if scope != nil && *scope != *actual {
		return nil, permission.NewAccessDenied("Root is outside the authorized Organization")
	}
	org, err := organization.NewStore(a.DB).FindNormalByID(ctx, *actual)
	if err != nil {
		return nil, err
	}
	return &graphql2.OrganizationSummary{ID: org.ID.String(), DisplayName: org.DisplayName}, nil
}

func (s *Service) Organization(ctx context.Context, r *service.Service) (*graphql2.OrganizationSummary, error) {
	return (*App)(s).rootOrganizationSummary(ctx, assignment.TargetTypeService, r.ID)
}
func (s *EscalationPolicy) Organization(ctx context.Context, r *escalation.Policy) (*graphql2.OrganizationSummary, error) {
	return (*App)(s).rootOrganizationSummary(ctx, assignment.TargetTypeEscalationPolicy, r.ID)
}
func (s *Schedule) Organization(ctx context.Context, r *schedule.Schedule) (*graphql2.OrganizationSummary, error) {
	return (*App)(s).rootOrganizationSummary(ctx, assignment.TargetTypeSchedule, r.ID)
}
func (s *Rotation) Organization(ctx context.Context, r *rotation.Rotation) (*graphql2.OrganizationSummary, error) {
	return (*App)(s).rootOrganizationSummary(ctx, assignment.TargetTypeRotation, r.ID)
}
