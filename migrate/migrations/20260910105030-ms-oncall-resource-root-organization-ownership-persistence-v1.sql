-- +migrate Up

ALTER TABLE public.services
    ADD COLUMN organization_id uuid NOT NULL
        CONSTRAINT services_organization_id_fkey
        REFERENCES public.normal_organizations (organization_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT;

ALTER TABLE public.schedules
    ADD COLUMN organization_id uuid NOT NULL
        CONSTRAINT schedules_organization_id_fkey
        REFERENCES public.normal_organizations (organization_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT;

ALTER TABLE public.rotations
    ADD COLUMN organization_id uuid NOT NULL
        CONSTRAINT rotations_organization_id_fkey
        REFERENCES public.normal_organizations (organization_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT;

ALTER TABLE public.escalation_policies
    ADD COLUMN organization_id uuid NOT NULL
        CONSTRAINT escalation_policies_organization_id_fkey
        REFERENCES public.normal_organizations (organization_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT;

-- +migrate Down

LOCK TABLE public.services, public.schedules, public.rotations, public.escalation_policies
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.services) OR
        EXISTS (SELECT 1 FROM public.schedules) OR
        EXISTS (SELECT 1 FROM public.rotations) OR
        EXISTS (SELECT 1 FROM public.escalation_policies) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'position-281 downgrade refused: resource rows retain Organization ownership';
    END IF;
END;
$$;

ALTER TABLE public.services DROP COLUMN organization_id;
ALTER TABLE public.schedules DROP COLUMN organization_id;
ALTER TABLE public.rotations DROP COLUMN organization_id;
ALTER TABLE public.escalation_policies DROP COLUMN organization_id;
