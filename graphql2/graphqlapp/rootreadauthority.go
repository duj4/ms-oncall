package graphqlapp

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation/validate"
)

// rootManagementHome returns Home attribution for the explicit management
// helpers only. A Default Home is never a Store business scope: each caller
// must resolve its approved operation's actual Normal target before Store I/O.
func rootManagementHome(ctx context.Context) (*uuid.UUID, error) {
	if auth.RequesterFromContext(ctx) == nil {
		return rootStoreOrganizationID(ctx)
	}
	ec, err := executioncontext.CheckHumanAuthority(ctx)
	if err != nil {
		return nil, err
	}
	home, _ := ec.HomeOrganizationID()
	if home.String() == organization.DefaultOrganizationID && !ec.Privileges().PlatformAdmin() {
		return nil, permission.NewAccessDenied("Normal Home or PlatformAdmin authority is required")
	}
	return &home, nil
}

func (a *App) normalRootTarget(ctx context.Context, typ assignment.TargetType, id string) (*uuid.UUID, error) {
	if err := validate.UUID("ID", id); err != nil {
		return nil, err
	}
	var table string
	switch typ {
	case assignment.TargetTypeService:
		table = "services"
	case assignment.TargetTypeEscalationPolicy:
		table = "escalation_policies"
	case assignment.TargetTypeSchedule:
		table = "schedules"
	case assignment.TargetTypeRotation:
		table = "rotations"
	default:
		return nil, permission.NewAccessDenied("Root read operation is not approved")
	}
	var target uuid.UUID
	query := `SELECT r.organization_id FROM ` + table + ` r
	 JOIN organizations o ON o.id=r.organization_id AND o.classification='NORMAL'
	 JOIN normal_organizations n ON n.organization_id=o.id AND n.organization_classification=o.classification
	 WHERE r.id=$1 AND o.id<>$2 AND o.id<>$3`
	if typ == assignment.TargetTypeService {
		query += ` AND EXISTS (SELECT 1 FROM escalation_policies p WHERE p.id=r.escalation_policy_id AND p.organization_id=r.organization_id)`
	}
	err := a.DB.QueryRowContext(ctx, query, id, organization.DefaultOrganizationID, uuid.Nil).Scan(&target)
	return &target, err
}

func (a *App) rootReadScope(ctx context.Context, typ assignment.TargetType, id string) (*uuid.UUID, error) {
	home, err := rootManagementHome(ctx)
	if err != nil || home == nil {
		return home, err
	}
	ec, err := executioncontext.CheckHumanAuthority(ctx)
	if err != nil {
		return nil, err
	}
	if !ec.Privileges().PlatformAdmin() {
		return home, nil
	}
	return a.normalRootTarget(ctx, typ, id)
}

// rootListScope validates each field's target independently. It never changes
// a request-wide selected Org and never derives authority from a cursor.
func (a *App) rootListScope(ctx context.Context, target *string) (*uuid.UUID, error) {
	home, err := rootManagementHome(ctx)
	if err != nil {
		return nil, err
	}
	if home == nil {
		if target != nil {
			return nil, permission.NewAccessDenied("Human target authority is required")
		}
		return nil, nil
	}
	ec, err := executioncontext.CheckHumanAuthority(ctx)
	if err != nil {
		return nil, err
	}
	if target == nil {
		if home.String() == organization.DefaultOrganizationID {
			return nil, permission.NewAccessDenied("explicit Normal target is required")
		}
		return home, nil
	}
	id, err := validate.ParseUUID("targetOrganizationID", *target)
	if err != nil {
		return nil, err
	}
	if !ec.Privileges().PlatformAdmin() && id != *home {
		return nil, permission.NewAccessDenied("target is outside Home Organization")
	}
	if _, err := organization.NewStore(a.DB).FindNormalByID(ctx, id); err != nil {
		return nil, permission.NewAccessDenied("Normal target is unavailable")
	}
	return &id, nil
}

// Each loader batch is partitioned by independently resolved persistent target.
// The same request can therefore read B and C without sharing mutable scope.
func loadScopedRoots[T any](ctx context.Context, a *App, typ assignment.TargetType, ids []string, find func(context.Context, []string, *uuid.UUID) ([]T, error)) ([]T, error) {
	var result []T
	for _, id := range ids {
		scope, err := a.rootReadScope(ctx, typ, id)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, err
		}
		values, err := find(ctx, []string{id}, scope)
		if err != nil {
			return nil, err
		}
		result = append(result, values...)
	}
	return result, nil
}
