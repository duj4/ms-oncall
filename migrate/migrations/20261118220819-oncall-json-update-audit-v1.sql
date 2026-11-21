-- +migrate Up

-- Independent OnCall JSON Update v1. Root survives. No destination payloads.
-- +migrate StatementBegin
CREATE FUNCTION schedule_oncall_update_rules_valid(schedule uuid,value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE item jsonb; previous text := ''; channel uuid; local_id integer;
BEGIN
    IF schedule='00000000-0000-0000-0000-000000000000' OR jsonb_typeof(value)<>'array' OR jsonb_array_length(value)>50 THEN RETURN false; END IF;
    FOR item IN SELECT * FROM jsonb_array_elements(value) LOOP
        IF jsonb_typeof(item)<>'object' OR
           (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(item) key) IS DISTINCT FROM ARRAY['channel_id','rule_id','time','weekdays'] OR
           jsonb_typeof(item->'rule_id')<>'string' OR jsonb_typeof(item->'channel_id')<>'string' OR
           jsonb_typeof(item->'time')<>'string' OR jsonb_typeof(item->'weekdays')<>'string' THEN RETURN false; END IF;
        IF (item->>'rule_id') COLLATE "C" <= previous COLLATE "C" OR item->>'rule_id' !~ ('^'||schedule::text||':(0|[1-9][0-9]?)$') THEN RETURN false; END IF;
        local_id := split_part(item->>'rule_id',':',2)::integer;
        IF local_id>=50 THEN RETURN false; END IF;
        previous := item->>'rule_id'; channel := (item->>'channel_id')::uuid;
        IF channel='00000000-0000-0000-0000-000000000000' OR channel::text<>item->>'channel_id' THEN RETURN false; END IF;
        IF item->>'time'='' THEN
            IF item->>'weekdays'<>'' THEN RETURN false; END IF;
        ELSIF item->>'time' !~ '^([01][0-9]|2[0-3]):[0-5][0-9]$' OR item->>'weekdays' !~ '^[01]{7}$' OR position('1' in item->>'weekdays')=0 THEN RETURN false; END IF;
    END LOOP;
    RETURN NOT EXISTS(SELECT FROM jsonb_array_elements(value) r GROUP BY r->>'channel_id',r->>'time' HAVING count(*)>1);
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
-- +migrate StatementEnd

-- SQL reconstructs the complete canonical diff. Counts are never trusted.
-- +migrate StatementBegin
CREATE FUNCTION schedule_oncall_update_rules_diff(b jsonb,a jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
WITH old AS (SELECT r->>'rule_id' id,r FROM jsonb_array_elements(b) r),
new AS (SELECT r->>'rule_id' id,r FROM jsonb_array_elements(a) r),
paired AS (SELECT coalesce(old.id,new.id) id,old.r b,new.r a FROM old FULL JOIN new USING(id)),
changes AS (
    SELECT id,'rule_removed' change FROM paired WHERE a IS NULL
    UNION ALL SELECT id,'rule_added' FROM paired WHERE b IS NULL
    UNION ALL SELECT id,'channel_replaced' FROM paired WHERE b IS NOT NULL AND a IS NOT NULL AND b->>'channel_id'<>a->>'channel_id'
    UNION ALL SELECT id,'trigger_replaced' FROM paired WHERE b IS NOT NULL AND a IS NOT NULL AND b->>'time'<>a->>'time'
    UNION ALL SELECT id,'trigger_trimmed' FROM paired WHERE b->>'time'=a->>'time' AND EXISTS(SELECT FROM generate_series(1,7) i WHERE substring(b->>'weekdays',i,1)='1' AND substring(a->>'weekdays',i,1)='0')
    UNION ALL SELECT id,'trigger_expanded' FROM paired WHERE b->>'time'=a->>'time' AND EXISTS(SELECT FROM generate_series(1,7) i WHERE substring(b->>'weekdays',i,1)='0' AND substring(a->>'weekdays',i,1)='1')
)
SELECT coalesce(jsonb_agg(jsonb_build_object('rule_id',id,'change',change,'source','EXPLICIT') ORDER BY id COLLATE "C",change COLLATE "C"),'[]'::jsonb) FROM changes;
$$;
-- +migrate StatementEnd

CREATE TABLE schedule_oncall_update_audit_events (
    event_id uuid PRIMARY KEY CHECK (event_id <> '00000000-0000-0000-0000-000000000000'),
    request_id uuid NOT NULL CHECK (request_id <> '00000000-0000-0000-0000-000000000000'),
    attempt_id uuid NOT NULL UNIQUE CHECK (attempt_id <> '00000000-0000-0000-0000-000000000000'),
    schema_version smallint NOT NULL CHECK (schema_version=1),
    root_type text NOT NULL DEFAULT 'schedule' CHECK (root_type='schedule'),
    operation text NOT NULL CHECK (operation='setScheduleOnCallNotificationRules'),
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
    before_rules jsonb NOT NULL CHECK (schedule_oncall_update_rules_valid(schedule_id,before_rules)),
    after_rules jsonb NOT NULL CHECK (schedule_oncall_update_rules_valid(schedule_id,after_rules)),
    effects jsonb NOT NULL CHECK (jsonb_typeof(effects)='array' AND effects=schedule_oncall_update_rules_diff(before_rules,after_rules)),
    effect_count integer NOT NULL CHECK (effect_count=jsonb_array_length(effects)),
    CHECK ((actor_kind='internal_system' AND actor_id IS NULL AND home_organization_id IS NULL AND authority_source='trusted_internal_system' AND authority_role='internal_system' AND organization_role='unknown') OR
        (actor_kind='human' AND actor_id IS NOT NULL AND actor_id <> '00000000-0000-0000-0000-000000000000' AND
         home_organization_id IS NOT NULL AND home_organization_id <> '00000000-0000-0000-0000-000000000000' AND
         authority_source='current_local_user_organization_at_admission' AND
         ((authority_role='org_admin' AND organization_role='ORG_ADMIN' AND home_organization_id=organization_id) OR
          (authority_role='platform_admin' AND (organization_role IN ('ORG_ADMIN','ORG_MEMBER') OR (organization_role='NONE' AND home_organization_id='296e2656-7221-53fe-bd0a-832d24ccfd03' AND home_organization_id<>organization_id))))))
);

CREATE INDEX schedule_oncall_update_audit_target_time ON schedule_oncall_update_audit_events(schedule_id,occurred_at,event_id);
CREATE INDEX schedule_oncall_update_audit_request ON schedule_oncall_update_audit_events(request_id);

-- +migrate StatementBegin
CREATE FUNCTION schedule_oncall_update_audit_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='schedule JSON update audit history is append-only';
END;
$$;
-- +migrate StatementEnd
CREATE TRIGGER schedule_oncall_update_audit_no_rewrite
BEFORE UPDATE OR DELETE OR TRUNCATE ON schedule_oncall_update_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION schedule_oncall_update_audit_append_only();
REVOKE ALL ON schedule_oncall_update_audit_events FROM PUBLIC;
REVOKE ALL ON FUNCTION schedule_oncall_update_rules_valid(uuid,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION schedule_oncall_update_rules_diff(jsonb,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION schedule_oncall_update_audit_append_only() FROM PUBLIC;

-- +migrate Down
-- No new audit retention or destructive downgrade policy is authorized.
-- +migrate StatementBegin
DO $$
BEGIN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='on-call JSON update audit downgrade refused: preserve audit history';
END;
$$;
-- +migrate StatementEnd
