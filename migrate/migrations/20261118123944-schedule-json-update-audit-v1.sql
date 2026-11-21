-- +migrate Up

-- A separate contract: the Schedule survives, no Root Delete contract changes.
-- UTC Unix nanoseconds (decimal strings), half-open intervals. No persistent JSON element IDs.
-- +migrate StatementBegin
CREATE FUNCTION schedule_json_update_coverage_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE item jsonb; canonical jsonb;
BEGIN
    IF jsonb_typeof(value) <> 'array' OR jsonb_array_length(value) > 10000 THEN RETURN false; END IF;
    FOR item IN SELECT * FROM jsonb_array_elements(value) LOOP
        IF jsonb_typeof(item) <> 'object' OR
           (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(item) key) IS DISTINCT FROM ARRAY['end_ns','kind','start_ns','user_id'] OR
           jsonb_typeof(item->'kind') <> 'string' OR jsonb_typeof(item->'user_id') <> 'string' OR
           jsonb_typeof(item->'start_ns') <> 'string' OR jsonb_typeof(item->'end_ns') <> 'string' OR
           (item->>'start_ns') !~ '^(0|-?[1-9][0-9]*)$' OR (item->>'end_ns') !~ '^(0|-?[1-9][0-9]*)$' THEN RETURN false; END IF;
        IF (item->>'start_ns')::numeric < -62135596800000000000 OR
           (item->>'end_ns')::numeric > 253402300799999999999 OR
           (item->>'start_ns')::numeric >= (item->>'end_ns')::numeric THEN RETURN false; END IF;
        IF item->>'kind' = 'temporary' THEN
            IF item->>'user_id' <> '' THEN RETURN false; END IF;
        ELSIF item->>'kind' = 'fixed_shift' THEN
            IF (item->>'user_id')::uuid = '00000000-0000-0000-0000-000000000000' OR
               (item->>'user_id')::uuid::text <> item->>'user_id' THEN RETURN false; END IF;
            IF NOT EXISTS (SELECT FROM jsonb_array_elements(value) t WHERE t->>'kind'='temporary'
                AND (t->>'start_ns')::numeric <= (item->>'start_ns')::numeric
                AND (t->>'end_ns')::numeric >= (item->>'end_ns')::numeric) THEN RETURN false; END IF;
        ELSE RETURN false; END IF;
    END LOOP;
    SELECT coalesce(jsonb_agg(jsonb_build_object('kind',kind,'user_id',uid,'start_ns',lower(r)::text,'end_ns',upper(r)::text)
        ORDER BY kind,uid,lower(r),upper(r)), '[]'::jsonb) INTO canonical
    FROM (SELECT c->>'kind' kind,c->>'user_id' uid,
          range_agg(numrange((c->>'start_ns')::numeric,(c->>'end_ns')::numeric,'[)')) ranges
          FROM jsonb_array_elements(value) entry(c) GROUP BY 1,2) grouped, unnest(ranges) r;
    RETURN value = canonical;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
-- +migrate StatementEnd

-- Database independently reconstructs the complete symmetric difference.
-- Omission, duplicate, invented effect, wrong source and wrong boundaries fail.
-- +migrate StatementBegin
CREATE FUNCTION schedule_json_update_coverage_diff(b jsonb,a jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
WITH coverage AS (
    SELECT 0 side,item FROM jsonb_array_elements(b) item
    UNION ALL SELECT 1,item FROM jsonb_array_elements(a) item
), groups AS (
    SELECT item->>'kind' kind,item->>'user_id' uid,
        coalesce(range_agg(numrange((item->>'start_ns')::numeric,(item->>'end_ns')::numeric,'[)')) FILTER(WHERE side=0),'{}'::nummultirange) br,
        coalesce(range_agg(numrange((item->>'start_ns')::numeric,(item->>'end_ns')::numeric,'[)')) FILTER(WHERE side=1),'{}'::nummultirange) ar
    FROM coverage GROUP BY 1,2
), effects AS (
    SELECT 0 side,kind,uid,unnest(br-ar) r,'coverage_removed' change FROM groups
    UNION ALL SELECT 1,kind,uid,unnest(ar-br),'coverage_added' FROM groups
)
SELECT coalesce(jsonb_agg(jsonb_build_object('kind',kind,'user_id',uid,'start_ns',lower(r)::text,'end_ns',upper(r)::text,'change',change,'source','EXPLICIT')
    ORDER BY side,kind,uid,lower(r),upper(r)), '[]'::jsonb) FROM effects;
$$;
-- +migrate StatementEnd

CREATE TABLE schedule_json_update_audit_events (
    event_id uuid PRIMARY KEY CHECK (event_id <> '00000000-0000-0000-0000-000000000000'),
    request_id uuid NOT NULL CHECK (request_id <> '00000000-0000-0000-0000-000000000000'),
    attempt_id uuid NOT NULL UNIQUE CHECK (attempt_id <> '00000000-0000-0000-0000-000000000000'),
    schema_version smallint NOT NULL CHECK (schema_version=1),
    root_type text NOT NULL DEFAULT 'schedule' CHECK (root_type='schedule'),
    operation text NOT NULL CHECK (operation IN ('setTemporarySchedule','clearTemporarySchedules')),
    update_mode text NOT NULL CHECK ((operation='setTemporarySchedule' AND update_mode IN ('set','set_clear')) OR (operation='clearTemporarySchedules' AND update_mode='clear')),
    actor_kind text NOT NULL,
    actor_id uuid,
    home_organization_id uuid,
    authority_source text NOT NULL,
    authority_role text NOT NULL,
    organization_role text NOT NULL,
    schedule_id uuid NOT NULL CHECK (schedule_id <> '00000000-0000-0000-0000-000000000000'),
    organization_id uuid NOT NULL CHECK (organization_id <> '00000000-0000-0000-0000-000000000000'),
    envelope_id bigint NOT NULL CHECK (envelope_id>0),
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at) AND occurred_at >= '0001-01-01 UTC' AND occurred_at < '10000-01-01 UTC'),
    before_coverage jsonb NOT NULL CHECK (schedule_json_update_coverage_valid(before_coverage)),
    after_coverage jsonb NOT NULL CHECK (schedule_json_update_coverage_valid(after_coverage)),
    effects jsonb NOT NULL CHECK (jsonb_typeof(effects)='array' AND effects=schedule_json_update_coverage_diff(before_coverage,after_coverage)),
    effect_count integer NOT NULL CHECK (effect_count=jsonb_array_length(effects)),
    CHECK (operation <> 'clearTemporarySchedules' OR NOT jsonb_path_exists(effects, '$[*] ? (@.change == "coverage_added")')),
    CHECK ((actor_kind='internal_system' AND actor_id IS NULL AND home_organization_id IS NULL AND authority_source='trusted_internal_system' AND authority_role='internal_system' AND organization_role='unknown') OR
        (actor_kind='human' AND actor_id IS NOT NULL AND actor_id <> '00000000-0000-0000-0000-000000000000' AND
         home_organization_id IS NOT NULL AND home_organization_id <> '00000000-0000-0000-0000-000000000000' AND
         authority_source='current_local_user_organization_at_admission' AND
         ((authority_role='org_admin' AND organization_role='ORG_ADMIN' AND home_organization_id=organization_id) OR
          (authority_role='platform_admin' AND (organization_role IN ('ORG_ADMIN','ORG_MEMBER') OR (organization_role='NONE' AND home_organization_id='296e2656-7221-53fe-bd0a-832d24ccfd03' AND home_organization_id<>organization_id))))))
);

CREATE INDEX schedule_json_update_audit_target_time ON schedule_json_update_audit_events(schedule_id,occurred_at,event_id);
CREATE INDEX schedule_json_update_audit_request ON schedule_json_update_audit_events(request_id);

-- +migrate StatementBegin
CREATE FUNCTION schedule_json_update_audit_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='schedule JSON update audit history is append-only';
END;
$$;
-- +migrate StatementEnd
CREATE TRIGGER schedule_json_update_audit_no_rewrite
BEFORE UPDATE OR DELETE OR TRUNCATE ON schedule_json_update_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION schedule_json_update_audit_append_only();
REVOKE ALL ON schedule_json_update_audit_events FROM PUBLIC;
REVOKE ALL ON FUNCTION schedule_json_update_coverage_valid(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION schedule_json_update_coverage_diff(jsonb,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION schedule_json_update_audit_append_only() FROM PUBLIC;

-- +migrate Down
-- No new audit retention or destructive downgrade policy is authorized.
-- +migrate StatementBegin
DO $$
BEGIN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='schedule JSON update audit downgrade refused: preserve audit history';
END;
$$;
-- +migrate StatementEnd
