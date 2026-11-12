-- +migrate Up

-- D09-SD7-UO: complete safe Override row version, no business child effects or live FK.
CREATE FUNCTION user_override_delete_before_valid(b jsonb, root uuid, parent uuid, org uuid) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE start_at timestamptz; end_at timestamptz; k text;
BEGIN
 IF jsonb_typeof(b)<>'object' OR NOT b ?& ARRAY['version','root_id','parent_schedule_id','target_organization_id','add_user_id','remove_user_id','start','end','row_version'] THEN RETURN false; END IF;
 FOR k IN SELECT jsonb_object_keys(b) LOOP
  IF k<>ALL(ARRAY['version','root_id','parent_schedule_id','target_organization_id','add_user_id','remove_user_id','start','end','row_version']) THEN RETURN false; END IF;
 END LOOP;
 IF b->'version'<>'1'::jsonb OR b->>'root_id' IS DISTINCT FROM root::text OR b->>'parent_schedule_id' IS DISTINCT FROM parent::text OR b->>'target_organization_id' IS DISTINCT FROM org::text THEN RETURN false; END IF;
 IF jsonb_typeof(b->'row_version')<>'number' OR (b->>'row_version')!~'^[1-9][0-9]{0,9}$' OR (b->>'row_version')::numeric>4294967295 THEN RETURN false; END IF;
 FOR k IN SELECT unnest(ARRAY['add_user_id','remove_user_id']) LOOP
  IF b->k<>'null'::jsonb AND (jsonb_typeof(b->k)<>'string' OR (b->>k)::uuid::text<>b->>k OR (b->>k)::uuid='00000000-0000-0000-0000-000000000000') THEN RETURN false; END IF;
 END LOOP;
 IF b->'add_user_id'='null'::jsonb AND b->'remove_user_id'='null'::jsonb THEN RETURN false; END IF;
 IF jsonb_typeof(b->'start')<>'string' OR jsonb_typeof(b->'end')<>'string' OR (b->>'start')!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$' OR (b->>'end')!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$' THEN RETURN false; END IF;
 start_at:=(b->>'start')::timestamptz; end_at:=(b->>'end')::timestamptz;
 RETURN isfinite(start_at) AND isfinite(end_at) AND extract(year FROM start_at AT TIME ZONE 'UTC') BETWEEN 1 AND 9999 AND extract(year FROM end_at AT TIME ZONE 'UTC') BETWEEN 1 AND 9999 AND end_at>start_at;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
CREATE TABLE user_override_delete_audit_events (
  schema_version smallint NOT NULL DEFAULT 1 CHECK(schema_version=1),
  event_id uuid PRIMARY KEY CHECK(event_id<>'00000000-0000-0000-0000-000000000000'),
  request_id uuid NOT NULL CHECK(request_id<>'00000000-0000-0000-0000-000000000000'),
  execution_id uuid NOT NULL CHECK(execution_id<>'00000000-0000-0000-0000-000000000000'),
  attempt_id uuid NOT NULL CHECK(attempt_id<>'00000000-0000-0000-0000-000000000000'),
  record_kind text NOT NULL CHECK(record_kind IN ('success_witness','attempt_observation')),
  operation text NOT NULL DEFAULT 'user_override.delete' CHECK(operation='user_override.delete'),
  root_type text NOT NULL DEFAULT 'user_override' CHECK(root_type='user_override'),
  root_id uuid CHECK(root_id<>'00000000-0000-0000-0000-000000000000'),
  parent_schedule_id uuid CHECK(parent_schedule_id<>'00000000-0000-0000-0000-000000000000'),
  target_organization_id uuid CHECK(target_organization_id<>'00000000-0000-0000-0000-000000000000'),
  target_org_resolution text NOT NULL,
  before_context jsonb NOT NULL DEFAULT 'null'::jsonb,
  effects jsonb NOT NULL DEFAULT '[]'::jsonb CHECK(effects='[]'::jsonb),
  provenance text,
  deletion_mechanism text,
  cause text,
  actor_kind text NOT NULL CHECK(actor_kind IN ('human','internal_system','unknown')),
  actor_id uuid CHECK(actor_id<>'00000000-0000-0000-0000-000000000000'),
  home_organization_id uuid CHECK(home_organization_id<>'00000000-0000-0000-0000-000000000000'),
  authority_source text NOT NULL,
  authority_role text NOT NULL,
  organization_role text NOT NULL,
  outcome text NOT NULL,
  reason_code text NOT NULL,
  occurred_at timestamptz NOT NULL CHECK(isfinite(occurred_at)),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(recorded_at)),
  CHECK (((root_id IS NULL AND parent_schedule_id IS NULL AND target_organization_id IS NULL AND target_org_resolution='unknown')
    OR (root_id IS NOT NULL AND parent_schedule_id IS NOT NULL AND target_organization_id IS NOT NULL AND (
      (target_org_resolution='known_normal' AND target_organization_id<>'296e2656-7221-53fe-bd0a-832d24ccfd03')
      OR (target_org_resolution='known_default' AND target_organization_id='296e2656-7221-53fe-bd0a-832d24ccfd03')))) IS TRUE),
  CHECK (((record_kind='success_witness' AND outcome='committed' AND reason_code='deleted' AND root_id IS NOT NULL AND user_override_delete_before_valid(before_context,root_id,parent_schedule_id,target_organization_id) IS TRUE AND provenance='EXPLICIT' AND deletion_mechanism='explicit_sql' AND cause='explicit_target')
    OR (record_kind='attempt_observation' AND before_context='null'::jsonb AND provenance IS NULL AND deletion_mechanism IS NULL AND cause IS NULL AND (
      (outcome='denied' AND reason_code='authority_denied')
      OR (outcome='validation_failed' AND reason_code IN ('invalid_fields','target_unavailable'))
      OR (outcome='tx_failed' AND reason_code IN ('begin_failed','write_failed','audit_write_failed','commit_rejected'))
      OR (outcome='commit_unknown' AND reason_code='commit_unconfirmed')
      OR (outcome='rollback_unconfirmed' AND reason_code='rollback_unconfirmed')))) IS TRUE),
  CHECK (((actor_kind='human' AND actor_id IS NOT NULL AND home_organization_id IS NOT NULL AND authority_source='current_local_user_organization_at_admission'
      AND ((home_organization_id='296e2656-7221-53fe-bd0a-832d24ccfd03' AND organization_role='NONE' AND authority_role IN ('platform_admin','none'))
        OR (home_organization_id<>'296e2656-7221-53fe-bd0a-832d24ccfd03' AND organization_role IN ('ORG_ADMIN','ORG_MEMBER')
          AND (authority_role='platform_admin' OR (authority_role='org_admin' AND organization_role='ORG_ADMIN') OR (authority_role='org_member' AND organization_role='ORG_MEMBER')))))
    OR (actor_kind='internal_system' AND actor_id IS NULL AND home_organization_id IS NULL AND authority_source='trusted_internal_system' AND authority_role='internal_system' AND organization_role='unknown')
    OR (actor_kind='unknown' AND actor_id IS NULL AND home_organization_id IS NULL AND authority_source='unknown' AND authority_role='unknown' AND organization_role='unknown')) IS TRUE),
  CHECK ((record_kind<>'success_witness' OR actor_kind='internal_system'
    OR (actor_kind='human' AND target_org_resolution='known_normal'
      AND home_organization_id=target_organization_id AND home_organization_id<>'296e2656-7221-53fe-bd0a-832d24ccfd03' AND authority_role IN ('org_member','org_admin','platform_admin'))) IS TRUE),
  CHECK(octet_length(jsonb_build_object('schema_version',schema_version,'event_id',event_id,'request_id',request_id,'execution_id',execution_id,'attempt_id',attempt_id,'record_kind',record_kind,'operation',operation,'root_type',root_type,'root_id',root_id,'parent_schedule_id',parent_schedule_id,'target_organization_id',target_organization_id,'target_org_resolution',target_org_resolution,'before_context',before_context,'effects',effects,'provenance',provenance,'deletion_mechanism',deletion_mechanism,'cause',cause,'actor_kind',actor_kind,'actor_id',actor_id,'home_organization_id',home_organization_id,'authority_source',authority_source,'authority_role',authority_role,'organization_role',organization_role,'outcome',outcome,'reason_code',reason_code,'occurred_at',occurred_at,'recorded_at',recorded_at)::text)<=4096)
);
CREATE UNIQUE INDEX user_override_delete_success_target ON user_override_delete_audit_events(attempt_id,root_id) WHERE record_kind='success_witness';
CREATE INDEX user_override_delete_correlation ON user_override_delete_audit_events(request_id,execution_id,attempt_id);
CREATE INDEX user_override_delete_root ON user_override_delete_audit_events(root_id,occurred_at,event_id);
CREATE INDEX user_override_delete_org ON user_override_delete_audit_events(target_organization_id,occurred_at,event_id);
CREATE INDEX user_override_delete_actor ON user_override_delete_audit_events(actor_id,occurred_at,event_id);
CREATE FUNCTION user_override_delete_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='user_override.delete audit is append-only';
END;
$$;
CREATE TRIGGER user_override_delete_no_change BEFORE UPDATE OR DELETE ON user_override_delete_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION user_override_delete_append_only();
CREATE TRIGGER user_override_delete_no_truncate BEFORE TRUNCATE ON user_override_delete_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION user_override_delete_append_only();
REVOKE ALL ON user_override_delete_audit_events FROM PUBLIC;
REVOKE ALL ON FUNCTION user_override_delete_append_only() FROM PUBLIC;
REVOKE ALL ON FUNCTION user_override_delete_before_valid(jsonb,uuid,uuid,uuid) FROM PUBLIC;

-- +migrate Down
DO $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='user_override.delete audit downgrade refused: preserve audit history';
END;
$$;
