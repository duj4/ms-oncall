package integrationkey

import (
	"context"
	"database/sql"
	"text/template"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/search"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation/validate"
)

// InKeySearchOptions allow filtering and paginating the list of rotations.
type InKeySearchOptions struct {
	Search  string `json:"s,omitempty"`
	After   string `json:"a,omitempty"`
	AfterID string `json:"i,omitempty"`

	// Omit specifies a list of key ids to exclude from the results.
	Omit []string `json:"o,omitempty"`

	Limit int `json:"-"`
}

var intKeySearchTemplate = template.Must(template.New("integration-key-search").Parse(`
	SELECT
		key.id, key.name, key.type, key.service_id
	FROM integration_keys key
	WHERE true
	{{if .PlatformAdminHome.Valid}}
		AND EXISTS (
			SELECT 1 FROM services s
			JOIN organizations o ON o.id = s.organization_id AND o.classification = 'NORMAL'
			JOIN normal_organizations n ON n.organization_id = o.id AND n.organization_classification = o.classification
			WHERE s.id = key.service_id AND s.organization_id <> :defaultOrganizationID
			AND (key.type IN ('generic','grafana','site24x7','prometheusAlertmanager','email')
				OR (key.type = 'universal' AND s.organization_id = :platformAdminHome))
		)
	{{end}}
	{{if .OrganizationID.Valid}}
		AND EXISTS (SELECT 1 FROM services s WHERE s.id = key.service_id AND s.organization_id = :organizationID)
	{{end}}
	{{if .Omit}}
		AND not key.id = any(:omit)
	{{end}}
	{{if .Search}}
		AND (key.id::text ILIKE :search)
	{{end}}
	{{if .After}}
		{{if .AfterID}}
			AND (lower(key.name), key.id) > (lower(:after), :afterID)
		{{else}}
			AND lower(key.name) > lower(:after)
		{{end}}
	{{end}}
	ORDER BY lower(key.name), key.id
	LIMIT {{.Limit}}
`))

type intKeyRenderData struct {
	InKeySearchOptions
	OrganizationID    uuid.NullUUID
	PlatformAdminHome uuid.NullUUID
}

func (opts intKeyRenderData) Normalize() (*intKeyRenderData, error) {
	if opts.Limit == 0 {
		opts.Limit = search.DefaultMaxResults
	}
	if opts.AfterID != "" {
		if err := validate.UUID("AfterID", opts.AfterID); err != nil {
			return nil, err
		}
	}

	err := validate.Many(
		validate.Search("Search", opts.Search),
		validate.Range("Limit", opts.Limit, 0, search.MaxResults),
		validate.Range("Omit", len(opts.Omit), 0, 50),
	)

	if err != nil {
		return nil, err
	}

	return &opts, err
}

func (opts intKeyRenderData) SearchStr() string {
	if opts.Search == "" {
		return ""
	}

	return search.Escape(opts.Search) + "%"
}

func (opts intKeyRenderData) QueryArgs() []sql.NamedArg {

	return []sql.NamedArg{
		sql.Named("search", opts.SearchStr()),
		sql.Named("organizationID", opts.OrganizationID),
		sql.Named("after", opts.After),
		sql.Named("afterID", opts.AfterID),
		sql.Named("platformAdminHome", opts.PlatformAdminHome),
		sql.Named("defaultOrganizationID", organization.DefaultOrganizationID),
		sql.Named("omit", sqlutil.StringArray(opts.Omit)),
	}
}

func (s *Store) Search(ctx context.Context, opts *InKeySearchOptions, organizationID *uuid.UUID) ([]IntegrationKey, error) {
	return s.search(ctx, opts, organizationID, uuid.NullUUID{})
}

// SearchForPlatformAdmin is a target constraint, not a Human authorization
// boundary. GraphQL must establish real PA authority first. The SQL predicate
// applies before LIMIT/cursor computation, including for pageInfo-only queries.
// Non-UIK keys are restricted to Normal Orgs; UIK remains Home-only.
func (s *Store) SearchForPlatformAdmin(ctx context.Context, opts *InKeySearchOptions, home uuid.UUID) ([]IntegrationKey, error) {
	if home == uuid.Nil || home.String() == organization.DefaultOrganizationID {
		return nil, permission.NewAccessDenied("normal Organization scope is required")
	}
	return s.search(ctx, opts, nil, uuid.NullUUID{UUID: home, Valid: true})
}

func (s *Store) search(ctx context.Context, opts *InKeySearchOptions, organizationID *uuid.UUID, paHome uuid.NullUUID) ([]IntegrationKey, error) {
	err := permission.LimitCheckAny(ctx, permission.User)
	if err != nil {
		return nil, err
	}
	if opts == nil {
		opts = &InKeySearchOptions{}
	}
	scope, err := organizationScope(organizationID)
	if err != nil {
		return nil, err
	}
	data, err := (intKeyRenderData{InKeySearchOptions: *opts, OrganizationID: scope, PlatformAdminHome: paHome}).Normalize()
	if err != nil {
		return nil, err
	}
	query, args, err := search.RenderQuery(ctx, intKeySearchTemplate, data)
	if err != nil {
		return nil, errors.Wrap(err, "render query")
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanIntegrationKeys(rows, false)
}

// FindNonUIKByService constrains a previously authorized foreign Normal Service
// parent without materializing foreign UIK objects through the shared list.
func (s *Store) FindNonUIKByService(ctx context.Context, serviceID string, organizationID uuid.UUID) ([]IntegrationKey, error) {
	if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
		return nil, err
	}
	id, err := validate.ParseUUID("ServiceID", serviceID)
	if err != nil {
		return nil, err
	}
	if organizationID == uuid.Nil || organizationID.String() == organization.DefaultOrganizationID {
		return nil, permission.NewAccessDenied("normal Organization scope is required")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT k.id, k.name, k.type, k.service_id, k.external_system_name FROM integration_keys k
		JOIN services s ON s.id = k.service_id
		JOIN organizations o ON o.id = s.organization_id AND o.classification = 'NORMAL'
		JOIN normal_organizations n ON n.organization_id = o.id AND n.organization_classification = o.classification
		WHERE s.id = $1 AND s.organization_id = $2
		AND k.type IN ('generic','grafana','site24x7','prometheusAlertmanager','email')
		ORDER BY lower(k.name), k.id
	`, id, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanIntegrationKeys(rows, true)
}

func scanIntegrationKeys(rows *sql.Rows, includeExternalSystemName bool) ([]IntegrationKey, error) {

	var result []IntegrationKey
	for rows.Next() {
		var intKey IntegrationKey
		var externalSystemName sql.NullString
		values := []any{&intKey.ID, &intKey.Name, &intKey.Type, &intKey.ServiceID}
		if includeExternalSystemName {
			values = append(values, &externalSystemName)
		}
		err := rows.Scan(values...)
		if err != nil {
			return nil, errors.Wrap(err, "scan row")
		}
		intKey.ExternalSystemName = externalSystemName.String
		result = append(result, intKey)
	}

	return result, rows.Err()
}
