-- +migrate Up

CREATE TYPE public.ms_oncall_user_organization_assignment_state AS ENUM (
    'ACTIVE',
    'TRANSITIONING'
);

CREATE TYPE public.ms_oncall_user_organization_role AS ENUM (
    'ORG_MEMBER',
    'ORG_ADMIN',
    'NONE'
);

CREATE TYPE public.ms_oncall_user_organization_mapping_outcome AS ENUM (
    'EXACTLY_ONE',
    'ZERO',
    'MULTIPLE'
);

CREATE TABLE public.user_organization_assignments (
    user_id uuid PRIMARY KEY
        CONSTRAINT user_organization_assignments_user_id_non_nil
        CHECK (user_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    effective_organization_id uuid NOT NULL
        CONSTRAINT user_organization_assignments_effective_organization_id_non_nil
        CHECK (effective_organization_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    effective_organization_classification public.ms_oncall_organization_classification NOT NULL,
    effective_normal_organization_id uuid,
    state public.ms_oncall_user_organization_assignment_state NOT NULL,
    organization_role public.ms_oncall_user_organization_role NOT NULL,
    assignment_generation bigint NOT NULL
        CONSTRAINT user_organization_assignments_generation_positive
        CHECK (assignment_generation > 0),
    mapping_outcome public.ms_oncall_user_organization_mapping_outcome NOT NULL,
    authoritative_evaluated_at timestamp with time zone NOT NULL
        CONSTRAINT user_organization_assignments_evaluated_at_finite
        CHECK (isfinite(authoritative_evaluated_at)),
    source_config_version text NOT NULL
        CONSTRAINT user_organization_assignments_source_config_version_not_blank
        -- Fixed Unicode White_Space boundary set. Keep synchronized with
        -- organization.sourceConfigVersionBoundaryWhitespace.
        CHECK (
            source_config_version = pg_catalog.btrim(
                source_config_version,
                pg_catalog.chr(9) || pg_catalog.chr(10) || pg_catalog.chr(11) ||
                pg_catalog.chr(12) || pg_catalog.chr(13) || pg_catalog.chr(32) ||
                pg_catalog.chr(133) || pg_catalog.chr(160) || pg_catalog.chr(5760) ||
                pg_catalog.chr(8192) || pg_catalog.chr(8193) || pg_catalog.chr(8194) ||
                pg_catalog.chr(8195) || pg_catalog.chr(8196) || pg_catalog.chr(8197) ||
                pg_catalog.chr(8198) || pg_catalog.chr(8199) || pg_catalog.chr(8200) ||
                pg_catalog.chr(8201) || pg_catalog.chr(8202) || pg_catalog.chr(8232) ||
                pg_catalog.chr(8233) || pg_catalog.chr(8239) || pg_catalog.chr(8287) ||
                pg_catalog.chr(12288)
            ) AND
            source_config_version <> ''
        ),
    matched_count integer NOT NULL,
    evidence_digest bytea NOT NULL
        CONSTRAINT user_organization_assignments_evidence_digest_sha256
        CHECK (
            octet_length(evidence_digest) = 32 AND
            evidence_digest <> '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea
        ),
    pending_transfer_id uuid,
    CONSTRAINT user_organization_assignments_user_id_fkey
        FOREIGN KEY (user_id)
        REFERENCES public.users (id)
        ON UPDATE RESTRICT
        ON DELETE CASCADE,
    CONSTRAINT user_organization_assignments_effective_organization_fkey
        FOREIGN KEY (effective_organization_id, effective_organization_classification)
        REFERENCES public.organizations (id, classification)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    CONSTRAINT user_org_assignments_effective_normal_organization_fkey
        FOREIGN KEY (effective_normal_organization_id)
        REFERENCES public.normal_organizations (organization_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    CONSTRAINT user_organization_assignments_mapping_truth CHECK (
        (
            mapping_outcome = 'EXACTLY_ONE' AND
            matched_count = 1 AND
            effective_organization_classification = 'NORMAL' AND
            effective_organization_id <> '296e2656-7221-53fe-bd0a-832d24ccfd03'::uuid AND
            effective_normal_organization_id IS NOT NULL AND
            effective_normal_organization_id = effective_organization_id AND
            organization_role IN ('ORG_MEMBER', 'ORG_ADMIN')
        ) OR (
            mapping_outcome = 'ZERO' AND
            matched_count = 0 AND
            effective_organization_classification = 'DEFAULT' AND
            effective_organization_id = '296e2656-7221-53fe-bd0a-832d24ccfd03'::uuid AND
            effective_normal_organization_id IS NULL AND
            organization_role = 'NONE'
        ) OR (
            mapping_outcome = 'MULTIPLE' AND
            matched_count > 1 AND
            effective_organization_classification = 'DEFAULT' AND
            effective_organization_id = '296e2656-7221-53fe-bd0a-832d24ccfd03'::uuid AND
            effective_normal_organization_id IS NULL AND
            organization_role = 'NONE'
        )
    ),
    CONSTRAINT user_organization_assignments_pending_transfer_state CHECK (
        pending_transfer_id IS NULL OR (
            state = 'TRANSITIONING' AND
            pending_transfer_id <> '00000000-0000-0000-0000-000000000000'::uuid
        )
    )
);

CREATE FUNCTION public.ms_oncall_enforce_user_organization_assignment_invariants() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.user_id IS DISTINCT FROM OLD.user_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'user_organization_assignments_user_id_immutable',
            SCHEMA = 'public',
            TABLE = 'user_organization_assignments',
            COLUMN = 'user_id',
            MESSAGE = 'UserOrganizationAssignment identity is immutable';
    END IF;

    IF NEW.assignment_generation < OLD.assignment_generation THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'user_organization_assignments_generation_monotonic',
            SCHEMA = 'public',
            TABLE = 'user_organization_assignments',
            COLUMN = 'assignment_generation',
            MESSAGE = 'UserOrganizationAssignment generation cannot decrease';
    END IF;

    IF NEW.assignment_generation = OLD.assignment_generation AND (
        NEW.effective_organization_id IS DISTINCT FROM OLD.effective_organization_id OR
        NEW.effective_organization_classification IS DISTINCT FROM OLD.effective_organization_classification OR
        NEW.effective_normal_organization_id IS DISTINCT FROM OLD.effective_normal_organization_id OR
        NEW.state IS DISTINCT FROM OLD.state OR
        NEW.organization_role IS DISTINCT FROM OLD.organization_role OR
        NEW.mapping_outcome IS DISTINCT FROM OLD.mapping_outcome OR
        NEW.pending_transfer_id IS DISTINCT FROM OLD.pending_transfer_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'user_organization_assignments_generation_required',
            SCHEMA = 'public',
            TABLE = 'user_organization_assignments',
            COLUMN = 'assignment_generation',
            MESSAGE = 'UserOrganizationAssignment state changes require a newer generation';
    END IF;

    IF NEW.authoritative_evaluated_at <= OLD.authoritative_evaluated_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'user_organization_assignments_evaluated_at_monotonic',
            SCHEMA = 'public',
            TABLE = 'user_organization_assignments',
            COLUMN = 'authoritative_evaluated_at',
            MESSAGE = 'UserOrganizationAssignment evaluation time must increase';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER user_organization_assignments_enforce_invariants
    BEFORE UPDATE ON public.user_organization_assignments
    FOR EACH ROW EXECUTE FUNCTION public.ms_oncall_enforce_user_organization_assignment_invariants();

-- +migrate Down

DROP TRIGGER user_organization_assignments_enforce_invariants ON public.user_organization_assignments;
DROP FUNCTION public.ms_oncall_enforce_user_organization_assignment_invariants();
DROP TABLE public.user_organization_assignments;
DROP TYPE public.ms_oncall_user_organization_mapping_outcome;
DROP TYPE public.ms_oncall_user_organization_role;
DROP TYPE public.ms_oncall_user_organization_assignment_state;
