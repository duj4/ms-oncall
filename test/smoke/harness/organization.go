package harness

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

const (
	// SmokeOrganizationID is the deterministic test-only NormalOrganization
	// that owns operational resource fixtures and the normal GraphQL principal.
	SmokeOrganizationID = "00000000-0000-0000-0000-000000000003"

	smokeOrganizationDisplayName         = "Smoke Test Normal Organization"
	smokeOrganizationCanonicalName       = "smoke-test.normal-organization"
	smokeOrganizationCorporateMappingKey = "smoke-test:normal-organization"
	smokeOrganizationTimeZone            = "Etc/UTC"
)

// ensureSmokeOrganization installs and verifies the deterministic test-only
// NormalOrganization whenever the target schema contains the Organization
// foundation. It is intentionally a fixture operation, not production
// bootstrap or fallback behavior.
func (h *Harness) ensureSmokeOrganization() {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, h.dbURL)
	require.NoError(h.t, err, "connect to install smoke Organization")
	defer conn.Close(ctx)

	var schemaReady bool
	err = conn.QueryRow(ctx, `
		SELECT to_regclass('public.organizations') IS NOT NULL
			AND to_regclass('public.normal_organizations') IS NOT NULL
	`).Scan(&schemaReady)
	require.NoError(h.t, err, "inspect smoke Organization schema")
	if !schemaReady {
		return
	}

	tx, err := conn.Begin(ctx)
	require.NoError(h.t, err, "begin smoke Organization fixture")
	defer func() { _ = tx.Rollback(context.Background()) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO public.organizations (
			id, classification, display_name, canonical_name
		) VALUES ($1, 'NORMAL', $2, $3)
		ON CONFLICT (id) DO NOTHING
	`, SmokeOrganizationID, smokeOrganizationDisplayName, smokeOrganizationCanonicalName)
	require.NoError(h.t, err, "install smoke Organization base")
	_, err = tx.Exec(ctx, `
		INSERT INTO public.normal_organizations (
			organization_id, organization_classification,
			corporate_mapping_key, iana_time_zone
		) VALUES ($1, 'NORMAL', $2, $3)
		ON CONFLICT (organization_id) DO NOTHING
	`, SmokeOrganizationID, smokeOrganizationCorporateMappingKey, smokeOrganizationTimeZone)
	require.NoError(h.t, err, "install smoke NormalOrganization subtype")

	var classification, displayName, canonicalName, subtypeClassification, mappingKey, timeZone string
	err = tx.QueryRow(ctx, `
		SELECT
			o.classification,
			o.display_name,
			o.canonical_name,
			n.organization_classification,
			n.corporate_mapping_key,
			n.iana_time_zone
		FROM public.organizations AS o
		JOIN public.normal_organizations AS n ON n.organization_id = o.id
		WHERE o.id = $1
	`, SmokeOrganizationID).Scan(
		&classification,
		&displayName,
		&canonicalName,
		&subtypeClassification,
		&mappingKey,
		&timeZone,
	)
	require.NoError(h.t, err, "read smoke NormalOrganization fixture")
	require.Equal(h.t, "NORMAL", classification)
	require.Equal(h.t, smokeOrganizationDisplayName, displayName)
	require.Equal(h.t, smokeOrganizationCanonicalName, canonicalName)
	require.Equal(h.t, "NORMAL", subtypeClassification)
	require.Equal(h.t, smokeOrganizationCorporateMappingKey, mappingKey)
	require.Equal(h.t, smokeOrganizationTimeZone, timeZone)
	require.NoError(h.t, tx.Commit(ctx), "commit smoke Organization fixture")
}

// ensureSmokeUserOrganizationAssignments gives users declared by smoke SQL a
// complete durable NormalOrganization admission record. Tests that need a
// missing or Default-restricted assignment create those users explicitly after
// harness initialization.
func (h *Harness) ensureSmokeUserOrganizationAssignments() {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, h.dbURL)
	require.NoError(h.t, err, "connect to install smoke user Organization assignments")
	defer conn.Close(ctx)

	var schemaReady bool
	err = conn.QueryRow(ctx, `
		SELECT to_regclass('public.user_organization_assignments') IS NOT NULL
	`).Scan(&schemaReady)
	require.NoError(h.t, err, "inspect smoke user Organization assignment schema")
	if !schemaReady {
		return
	}

	_, err = conn.Exec(ctx, `
		INSERT INTO public.user_organization_assignments (
			user_id,
			effective_organization_id,
			effective_organization_classification,
			effective_normal_organization_id,
			organization_role,
			mapping_outcome,
			authoritative_evaluated_at,
			source_config_version,
			matched_count
		)
		SELECT
			u.id,
			$1,
			'NORMAL',
			$1,
			'ORG_MEMBER',
			'EXACTLY_ONE',
			now(),
			'smoke-harness-v1',
			1
		FROM public.users AS u
		ON CONFLICT (user_id) DO NOTHING
	`, SmokeOrganizationID)
	require.NoError(h.t, err, "install smoke user Organization assignments")
}
