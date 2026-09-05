-- +migrate Up

DROP TRIGGER user_human_security_generations_enforce_invariants ON public.user_human_security_generations;
DROP FUNCTION public.ms_oncall_enforce_user_human_security_generation_invariants();
DROP TABLE public.user_human_security_generations;

-- +migrate Down

CREATE TABLE public.user_human_security_generations (
    user_id uuid PRIMARY KEY
        CONSTRAINT user_human_security_generations_user_id_non_nil
        CHECK (user_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    human_security_generation bigint NOT NULL DEFAULT 1
        CONSTRAINT user_human_security_generations_generation_positive
        CHECK (human_security_generation > 0),
    CONSTRAINT user_human_security_generations_user_id_fkey
        FOREIGN KEY (user_id)
        REFERENCES public.users (id)
        ON UPDATE RESTRICT
        ON DELETE CASCADE
);

CREATE FUNCTION public.ms_oncall_enforce_user_human_security_generation_invariants() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.human_security_generation IS DISTINCT FROM 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'user_human_security_generations_initial_generation',
                SCHEMA = 'public',
                TABLE = 'user_human_security_generations',
                COLUMN = 'human_security_generation',
                MESSAGE = 'human security generation must begin at one';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.user_id IS DISTINCT FROM OLD.user_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'user_human_security_generations_user_id_immutable',
            SCHEMA = 'public',
            TABLE = 'user_human_security_generations',
            COLUMN = 'user_id',
            MESSAGE = 'human security generation User identity is immutable';
    END IF;

    -- Branch before adding so validation never evaluates bigint max + 1.
    IF OLD.human_security_generation = 9223372036854775807 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'user_human_security_generations_generation_step',
            SCHEMA = 'public',
            TABLE = 'user_human_security_generations',
            COLUMN = 'human_security_generation',
            MESSAGE = 'human security generation cannot advance beyond bigint maximum';
    ELSIF NEW.human_security_generation IS DISTINCT FROM OLD.human_security_generation + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'user_human_security_generations_generation_step',
            SCHEMA = 'public',
            TABLE = 'user_human_security_generations',
            COLUMN = 'human_security_generation',
            MESSAGE = 'human security generation must advance by exactly one';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER user_human_security_generations_enforce_invariants
    BEFORE INSERT OR UPDATE ON public.user_human_security_generations
    FOR EACH ROW EXECUTE FUNCTION public.ms_oncall_enforce_user_human_security_generation_invariants();
