-- +migrate Up

DROP TRIGGER user_organization_assignments_enforce_invariants ON public.user_organization_assignments;
DROP FUNCTION public.ms_oncall_enforce_user_organization_assignment_invariants();

ALTER TABLE public.user_organization_assignments
    DROP COLUMN state,
    DROP COLUMN assignment_generation,
    DROP COLUMN evidence_digest,
    DROP COLUMN pending_transfer_id;

DROP TYPE public.ms_oncall_user_organization_assignment_state;

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

    RETURN NEW;
END;
$$;

CREATE TRIGGER user_organization_assignments_enforce_invariants
    BEFORE UPDATE ON public.user_organization_assignments
    FOR EACH ROW EXECUTE FUNCTION public.ms_oncall_enforce_user_organization_assignment_invariants();

DROP TRIGGER organizations_enforce_invariants ON public.organizations;
DROP FUNCTION public.ms_oncall_enforce_organization_invariants();

ALTER TABLE public.organizations DROP COLUMN lifecycle;
DROP TYPE public.ms_oncall_organization_lifecycle;

CREATE FUNCTION public.ms_oncall_enforce_organization_invariants() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.classification = 'DEFAULT' THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'organizations_default_delete_forbidden',
                SCHEMA = 'public',
                TABLE = 'organizations',
                COLUMN = 'classification',
                MESSAGE = 'the distinguished Default Organization cannot be deleted';
        END IF;
        RETURN OLD;
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'organizations_id_immutable',
            SCHEMA = 'public',
            TABLE = 'organizations',
            COLUMN = 'id',
            MESSAGE = 'Organization identity is immutable';
    END IF;
    IF NEW.classification IS DISTINCT FROM OLD.classification THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'organizations_classification_immutable',
            SCHEMA = 'public',
            TABLE = 'organizations',
            COLUMN = 'classification',
            MESSAGE = 'Organization classification is immutable';
    END IF;
    IF NEW.canonical_name IS DISTINCT FROM OLD.canonical_name THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'organizations_canonical_name_immutable',
            SCHEMA = 'public',
            TABLE = 'organizations',
            COLUMN = 'canonical_name',
            MESSAGE = 'Organization canonical identity is immutable';
    END IF;
    IF NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'organizations_created_at_immutable',
            SCHEMA = 'public',
            TABLE = 'organizations',
            COLUMN = 'created_at',
            MESSAGE = 'Organization creation timestamp is immutable';
    END IF;

    IF NEW.display_name IS DISTINCT FROM OLD.display_name OR
        NEW.updated_at IS DISTINCT FROM OLD.updated_at THEN
        NEW.updated_at = greatest(clock_timestamp(), OLD.updated_at + interval '1 microsecond');
    ELSE
        NEW.updated_at = OLD.updated_at;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER organizations_enforce_invariants
    BEFORE UPDATE OR DELETE ON public.organizations
    FOR EACH ROW EXECUTE FUNCTION public.ms_oncall_enforce_organization_invariants();

-- +migrate Down

LOCK TABLE public.organizations, public.normal_organizations, public.user_organization_assignments
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.user_organization_assignments) OR
        EXISTS (SELECT 1 FROM public.normal_organizations) OR
        (SELECT count(*) FROM public.organizations) <> 1 OR
        NOT EXISTS (
            SELECT 1
            FROM public.organizations
            WHERE id = '296e2656-7221-53fe-bd0a-832d24ccfd03'::uuid
                AND classification = 'DEFAULT'
                AND canonical_name = 'ms-oncall.default'
        ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'position-280 downgrade refused: current Organization or assignment rows require discarded authority state';
    END IF;
END;
$$;

DROP TRIGGER organizations_enforce_invariants ON public.organizations;
DROP FUNCTION public.ms_oncall_enforce_organization_invariants();

CREATE TYPE public.ms_oncall_organization_lifecycle AS ENUM (
    'ACTIVE',
    'SUSPENDED',
    'RETIRED'
);

ALTER TABLE public.organizations
    ADD COLUMN lifecycle public.ms_oncall_organization_lifecycle NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE public.organizations ALTER COLUMN lifecycle DROP DEFAULT;

CREATE FUNCTION public.ms_oncall_enforce_organization_invariants() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.classification = 'DEFAULT' THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'organizations_default_delete_forbidden',
                SCHEMA = 'public',
                TABLE = 'organizations',
                COLUMN = 'classification',
                MESSAGE = 'the distinguished Default Organization cannot be deleted';
        END IF;
        RETURN OLD;
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'organizations_id_immutable',
            SCHEMA = 'public',
            TABLE = 'organizations',
            COLUMN = 'id',
            MESSAGE = 'Organization identity is immutable';
    END IF;
    IF NEW.classification IS DISTINCT FROM OLD.classification THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'organizations_classification_immutable',
            SCHEMA = 'public',
            TABLE = 'organizations',
            COLUMN = 'classification',
            MESSAGE = 'Organization classification is immutable';
    END IF;
    IF NEW.canonical_name IS DISTINCT FROM OLD.canonical_name THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'organizations_canonical_name_immutable',
            SCHEMA = 'public',
            TABLE = 'organizations',
            COLUMN = 'canonical_name',
            MESSAGE = 'Organization canonical identity is immutable';
    END IF;
    IF NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'organizations_created_at_immutable',
            SCHEMA = 'public',
            TABLE = 'organizations',
            COLUMN = 'created_at',
            MESSAGE = 'Organization creation timestamp is immutable';
    END IF;

    IF NEW.lifecycle IS DISTINCT FROM OLD.lifecycle THEN
        IF OLD.classification = 'DEFAULT' THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'organizations_default_lifecycle_immutable',
                SCHEMA = 'public',
                TABLE = 'organizations',
                COLUMN = 'lifecycle',
                MESSAGE = 'the distinguished Default Organization lifecycle is immutable';
        END IF;
        IF NOT (
            (OLD.lifecycle = 'ACTIVE' AND NEW.lifecycle IN ('SUSPENDED', 'RETIRED')) OR
            (OLD.lifecycle = 'SUSPENDED' AND NEW.lifecycle IN ('ACTIVE', 'RETIRED'))
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'organizations_lifecycle_transition',
                SCHEMA = 'public',
                TABLE = 'organizations',
                COLUMN = 'lifecycle',
                MESSAGE = 'invalid Organization lifecycle transition';
        END IF;
    END IF;

    IF NEW.display_name IS DISTINCT FROM OLD.display_name OR
        NEW.lifecycle IS DISTINCT FROM OLD.lifecycle OR
        NEW.updated_at IS DISTINCT FROM OLD.updated_at THEN
        NEW.updated_at = greatest(clock_timestamp(), OLD.updated_at + interval '1 microsecond');
    ELSE
        NEW.updated_at = OLD.updated_at;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER organizations_enforce_invariants
    BEFORE UPDATE OR DELETE ON public.organizations
    FOR EACH ROW EXECUTE FUNCTION public.ms_oncall_enforce_organization_invariants();

DROP TRIGGER user_organization_assignments_enforce_invariants ON public.user_organization_assignments;
DROP FUNCTION public.ms_oncall_enforce_user_organization_assignment_invariants();

CREATE TYPE public.ms_oncall_user_organization_assignment_state AS ENUM (
    'ACTIVE',
    'TRANSITIONING'
);

ALTER TABLE public.user_organization_assignments
    ADD COLUMN state public.ms_oncall_user_organization_assignment_state NOT NULL DEFAULT 'ACTIVE',
    ADD COLUMN assignment_generation bigint NOT NULL DEFAULT 1
        CONSTRAINT user_organization_assignments_generation_positive CHECK (assignment_generation > 0),
    ADD COLUMN evidence_digest bytea NOT NULL
        DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000001'::bytea
        CONSTRAINT user_organization_assignments_evidence_digest_sha256 CHECK (
            octet_length(evidence_digest) = 32 AND
            evidence_digest <> '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea
        ),
    ADD COLUMN pending_transfer_id uuid;

ALTER TABLE public.user_organization_assignments
    ALTER COLUMN state DROP DEFAULT,
    ALTER COLUMN assignment_generation DROP DEFAULT,
    ALTER COLUMN evidence_digest DROP DEFAULT,
    ADD CONSTRAINT user_organization_assignments_pending_transfer_state CHECK (
        pending_transfer_id IS NULL OR (
            state = 'TRANSITIONING' AND
            pending_transfer_id <> '00000000-0000-0000-0000-000000000000'::uuid
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
