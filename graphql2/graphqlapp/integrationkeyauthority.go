package graphqlapp

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/integrationkey"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

// integrationKeyAuthority is local to this GraphQL capability. Human authority
// comes from canonical request admission (current PostgreSQL User/Home/role),
// never a caller-supplied Organization or the legacy Admin bit alone.
type integrationKeyAuthority struct {
	home          *uuid.UUID
	platformAdmin bool
	system        bool
}

func integrationKeyAccessDenied() error {
	return permission.NewAccessDenied("Integration Key management authority is required")
}

func integrationKeyManagementAuthority(ctx context.Context) (*integrationKeyAuthority, error) {
	home, err := rootStoreOrganizationID(ctx)
	if err != nil {
		return nil, integrationKeyAccessDenied()
	}
	ec := executioncontext.ExecutionContextFromContext(ctx)
	if home == nil {
		// Preserve explicit trusted System/Engine calls, not an implicit nil-scope
		// Global grant to a source-less User/Admin, Machine or integration caller.
		if permission.System(ctx) && permission.UserID(ctx) == "" &&
			auth.RequesterFromContext(ctx) == nil && ec == nil && permission.Source(ctx) == nil {
			return &integrationKeyAuthority{system: true}, nil
		}
		return nil, integrationKeyAccessDenied()
	}
	if permission.System(ctx) || ec == nil || ec.Privileges() == nil {
		return nil, integrationKeyAccessDenied()
	}
	p := ec.Privileges()
	if p.PlatformAdmin() != permission.Admin(ctx) ||
		(p.OrganizationRole() != organization.OrganizationRoleAdmin && !p.PlatformAdmin()) {
		return nil, integrationKeyAccessDenied()
	}
	return &integrationKeyAuthority{home: home, platformAdmin: p.PlatformAdmin()}, nil
}

// targetOrganization returns a concrete Store constraint for every Human
// target. UIK reads/creation retain their existing Home-only scope, even for PA.
func (a *integrationKeyAuthority) targetOrganization(id uuid.UUID, kind integrationkey.Type) (*uuid.UUID, error) {
	if a.system { // Explicit System compatibility, established above.
		return nil, nil
	}
	if a.home == nil || id == uuid.Nil || id.String() == organization.DefaultOrganizationID {
		return nil, integrationKeyAccessDenied()
	}
	switch kind {
	case integrationkey.TypeGeneric, integrationkey.TypeGrafana, integrationkey.TypeSite24x7,
		integrationkey.TypePrometheusAlertmanager, integrationkey.TypeEmail:
		if a.platformAdmin || id == *a.home {
			return &id, nil
		}
	case integrationkey.TypeUniversal:
		if id == *a.home {
			return &id, nil
		}
	}
	return nil, integrationKeyAccessDenied()
}

const integrationKeyNormalServiceJoin = `
	JOIN organizations o ON o.id = s.organization_id AND o.classification = 'NORMAL'
	JOIN normal_organizations n ON n.organization_id = o.id
		AND n.organization_classification = o.classification
`

// keyTarget resolves the actual DB-owned type and Key -> Service -> Normal Org
// relationship. raw.Type and raw.ServiceID are never authorization evidence.
func (a *integrationKeyAuthority) keyTarget(ctx context.Context, dbtx gadb.DBTX, id string) (*uuid.UUID, integrationkey.Type, error) {
	keyID, err := uuid.Parse(id)
	if err != nil || keyID == uuid.Nil {
		return nil, "", integrationKeyAccessDenied()
	}
	var org uuid.UUID
	var kind integrationkey.Type
	if a.system {
		err = dbtx.QueryRowContext(ctx, `SELECT type FROM integration_keys WHERE id = $1`, keyID).Scan(&kind)
	} else {
		err = dbtx.QueryRowContext(ctx, `
		SELECT s.organization_id, k.type FROM integration_keys k
		JOIN services s ON s.id = k.service_id
	`+integrationKeyNormalServiceJoin+`
		WHERE k.id = $1 AND s.organization_id <> $2
	`, keyID, organization.DefaultOrganizationID).Scan(&org, &kind)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", integrationKeyAccessDenied()
	}
	if err != nil {
		return nil, "", err
	}
	scope, err := a.targetOrganization(org, kind)
	return scope, kind, err
}

// serviceTarget uses the caller's transaction so a newly created parent is
// visible before Key generation, while the existing FK/transaction semantics
// remain authoritative for persistence.
func (a *integrationKeyAuthority) serviceTarget(ctx context.Context, dbtx gadb.DBTX, id string, kind integrationkey.Type) (*uuid.UUID, error) {
	if a.system {
		return nil, nil
	}
	serviceID, err := uuid.Parse(id)
	if err != nil || serviceID == uuid.Nil {
		return nil, integrationKeyAccessDenied()
	}
	var org uuid.UUID
	err = dbtx.QueryRowContext(ctx, `
		SELECT s.organization_id FROM services s
	`+integrationKeyNormalServiceJoin+`
		WHERE s.id = $1 AND s.organization_id <> $2
	`, serviceID, organization.DefaultOrganizationID).Scan(&org)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, integrationKeyAccessDenied()
	}
	if err != nil {
		return nil, err
	}
	return a.targetOrganization(org, kind)
}
