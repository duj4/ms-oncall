-- +migrate Up

CREATE TYPE public.ms_oncall_organization_classification AS ENUM (
    'NORMAL',
    'DEFAULT'
);

CREATE TYPE public.ms_oncall_organization_lifecycle AS ENUM (
    'ACTIVE',
    'SUSPENDED',
    'RETIRED'
);

CREATE TABLE public.organizations (
    id uuid PRIMARY KEY,
    classification public.ms_oncall_organization_classification NOT NULL,
    display_name text NOT NULL CONSTRAINT organizations_display_name_not_blank
        CHECK (btrim(display_name) <> ''),
    canonical_name text NOT NULL CONSTRAINT organizations_canonical_name_not_blank
        CHECK (canonical_name = btrim(canonical_name) AND canonical_name <> ''),
    lifecycle public.ms_oncall_organization_lifecycle NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamp with time zone NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT organizations_canonical_name_key UNIQUE (canonical_name),
    CONSTRAINT organizations_id_classification_key UNIQUE (id, classification),
    CONSTRAINT organizations_audit_timestamp_order CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX organizations_single_default_idx
    ON public.organizations ((classification))
    WHERE classification = 'DEFAULT';

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

CREATE TABLE public.normal_organizations (
    organization_id uuid PRIMARY KEY,
    organization_classification public.ms_oncall_organization_classification NOT NULL DEFAULT 'NORMAL'
        CONSTRAINT normal_organizations_classification_normal CHECK (organization_classification = 'NORMAL'),
    corporate_mapping_key text NOT NULL
        CONSTRAINT normal_organizations_corporate_mapping_key_not_blank
        CHECK (corporate_mapping_key = btrim(corporate_mapping_key) AND corporate_mapping_key <> ''),
    iana_time_zone text NOT NULL
        CONSTRAINT normal_organizations_iana_time_zone_not_blank CHECK (btrim(iana_time_zone) <> ''),
    CONSTRAINT normal_organizations_corporate_mapping_key_key UNIQUE (corporate_mapping_key),
    CONSTRAINT normal_organizations_organization_classification_fkey
        FOREIGN KEY (organization_id, organization_classification)
        REFERENCES public.organizations (id, classification)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
);

CREATE FUNCTION public.ms_oncall_enforce_normal_organization_invariants() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'normal_organizations_organization_id_immutable',
            SCHEMA = 'public',
            TABLE = 'normal_organizations',
            COLUMN = 'organization_id',
            MESSAGE = 'Normal Organization identity is immutable';
    END IF;
    IF NEW.organization_classification IS DISTINCT FROM OLD.organization_classification THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'normal_organizations_classification_immutable',
            SCHEMA = 'public',
            TABLE = 'normal_organizations',
            COLUMN = 'organization_classification',
            MESSAGE = 'Normal Organization classification is immutable';
    END IF;
    IF NEW.corporate_mapping_key IS DISTINCT FROM OLD.corporate_mapping_key THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'normal_organizations_corporate_mapping_key_immutable',
            SCHEMA = 'public',
            TABLE = 'normal_organizations',
            COLUMN = 'corporate_mapping_key',
            MESSAGE = 'Normal Organization corporate mapping key is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER normal_organizations_enforce_invariants
    BEFORE UPDATE ON public.normal_organizations
    FOR EACH ROW EXECUTE FUNCTION public.ms_oncall_enforce_normal_organization_invariants();

CREATE FUNCTION public.ms_oncall_touch_organization_from_normal_organization() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.iana_time_zone IS DISTINCT FROM OLD.iana_time_zone THEN
        UPDATE public.organizations
        SET updated_at = clock_timestamp()
        WHERE id = NEW.organization_id AND classification = 'NORMAL';

        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'normal_organizations_base_invariant',
                SCHEMA = 'public',
                TABLE = 'organizations',
                COLUMN = 'id',
                MESSAGE = 'Normal Organization base invariant is missing';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER normal_organizations_touch_base
    AFTER UPDATE OF iana_time_zone ON public.normal_organizations
    FOR EACH ROW EXECUTE FUNCTION public.ms_oncall_touch_organization_from_normal_organization();

INSERT INTO public.organizations (
    id,
    classification,
    display_name,
    canonical_name,
    lifecycle
) VALUES (
    '296e2656-7221-53fe-bd0a-832d24ccfd03',
    'DEFAULT',
    'Default Organization',
    'ms-oncall.default',
    'ACTIVE'
);

DO $$
BEGIN
    IF (SELECT count(*) FROM public.organizations WHERE classification = 'DEFAULT') <> 1 THEN
        RAISE EXCEPTION 'distinguished Default Organization bootstrap did not produce exactly one row';
    END IF;
END;
$$;

-- +migrate Down

DROP TRIGGER normal_organizations_touch_base ON public.normal_organizations;
DROP FUNCTION public.ms_oncall_touch_organization_from_normal_organization();
DROP TRIGGER normal_organizations_enforce_invariants ON public.normal_organizations;
DROP FUNCTION public.ms_oncall_enforce_normal_organization_invariants();
DROP TABLE public.normal_organizations;
DROP TRIGGER organizations_enforce_invariants ON public.organizations;
DROP FUNCTION public.ms_oncall_enforce_organization_invariants();
DROP TABLE public.organizations;
DROP TYPE public.ms_oncall_organization_lifecycle;
DROP TYPE public.ms_oncall_organization_classification;
