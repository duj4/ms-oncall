-- +migrate Up

CREATE FUNCTION escalation_policy_delete_effects_valid(effects jsonb,root uuid,org uuid) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE f jsonb; k text; v jsonb; expected text[];
BEGIN
 IF effects IS NULL OR jsonb_typeof(effects)<>'array' THEN RETURN false; END IF;
 IF jsonb_array_length(effects)>16384 OR octet_length(effects::text)>8388608 THEN RETURN false; END IF;
 -- Set checks avoid repeated materialization of the full effects array for each
 -- action and avoid quadratic identity-array growth at the accepted boundary.
 IF (SELECT count(DISTINCT (value->>'effect_id')::uuid) FROM jsonb_array_elements(effects))<>jsonb_array_length(effects) THEN RETURN false; END IF;
 IF (SELECT count(DISTINCT ROW(value->>'resource_type',coalesce((value->>'resource_uuid')::uuid::text,(value->>'resource_numeric_id')::bigint::text))) FROM jsonb_array_elements(effects))<>jsonb_array_length(effects) THEN RETURN false; END IF;
 IF EXISTS(
  (SELECT (value->>'parent_step_id')::uuid FROM jsonb_array_elements(effects) WHERE value->>'resource_type'='escalation_policy_action')
  EXCEPT
  (SELECT (value->>'resource_uuid')::uuid FROM jsonb_array_elements(effects) WHERE value->>'resource_type'='escalation_policy_step')
 ) THEN RETURN false; END IF;
 FOR f IN SELECT value FROM jsonb_array_elements(effects) LOOP
  IF jsonb_typeof(f)<>'object' THEN RETURN false; END IF;
  CASE f->>'resource_type'
   WHEN 'escalation_policy_step' THEN expected=ARRAY['effect_id','resource_type','root_id','target_organization_id','relation','change','provenance','deletion_mechanism','cause','resource_uuid','step_number']::text[];
   WHEN 'escalation_policy_action' THEN expected=ARRAY['effect_id','resource_type','root_id','target_organization_id','relation','change','provenance','deletion_mechanism','cause','resource_uuid','parent_step_id','target_kind','target_id']::text[];
   WHEN 'escalation_policy_favorite' THEN
    expected=ARRAY['effect_id','resource_type','root_id','target_organization_id','relation','change','provenance','deletion_mechanism','cause','resource_numeric_id','owner_user_id','owner_org_resolution']::text[];
    IF f->>'owner_org_resolution' IN ('known_normal','known_default') THEN expected=array_append(expected,'owner_organization_id'); END IF;
   ELSE RETURN false;
  END CASE;
  IF NOT (f ?& expected) OR (SELECT count(*) FROM jsonb_object_keys(f))<>cardinality(expected) THEN RETURN false; END IF;
  FOR k,v IN SELECT * FROM jsonb_each(f) LOOP
   IF k IN ('step_number','resource_numeric_id') THEN
    IF jsonb_typeof(v)<>'number' OR v::text !~ '^[0-9]+$' THEN RETURN false; END IF;
   ELSIF jsonb_typeof(v)<>'string' THEN RETURN false;
   END IF;
   IF k IN ('effect_id','root_id','target_organization_id','resource_uuid','parent_step_id','target_id','owner_user_id','owner_organization_id') THEN
    IF (f->>k)::uuid='00000000-0000-0000-0000-000000000000' THEN RETURN false; END IF;
   END IF;
  END LOOP;
  IF ((f->>'root_id')::uuid=root AND (f->>'target_organization_id')::uuid=org
    AND f->>'provenance'='CASCADE' AND f->>'deletion_mechanism'='fk_cascade'
    AND f->>'cause'='escalation_policy_delete') IS NOT TRUE THEN RETURN false; END IF;
  CASE f->>'resource_type'
   WHEN 'escalation_policy_step' THEN
    IF (f->>'relation'='escalation_policy.step' AND f->>'change'='deleted' AND (f->>'step_number')::integer>=0) IS NOT TRUE THEN RETURN false; END IF;
   WHEN 'escalation_policy_action' THEN
    IF (f->>'relation'='escalation_policy.step.action' AND f->>'change'='deleted' AND f->>'target_kind' IN ('user','schedule','rotation','notification_channel')) IS NOT TRUE THEN RETURN false; END IF;
   WHEN 'escalation_policy_favorite' THEN
    IF (f->>'relation'='escalation_policy.favorite' AND f->>'change'='relationship_removed' AND (f->>'resource_numeric_id')::bigint>0) IS NOT TRUE THEN RETURN false; END IF;
    IF (f->>'owner_org_resolution'='unknown'
      OR (f->>'owner_org_resolution'='known_normal' AND (f->>'owner_organization_id')::uuid<>'296e2656-7221-53fe-bd0a-832d24ccfd03')
      OR (f->>'owner_org_resolution'='known_default' AND (f->>'owner_organization_id')::uuid='296e2656-7221-53fe-bd0a-832d24ccfd03')) IS NOT TRUE THEN RETURN false; END IF;
  END CASE;
 END LOOP;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;

-- D09-SD5: closed historical EP/Step/Action/Favorite identities. No live FK.
CREATE TABLE escalation_policy_delete_audit_events (
  schema_version smallint NOT NULL DEFAULT 1 CHECK(schema_version=1),
  event_id uuid PRIMARY KEY CHECK(event_id<>'00000000-0000-0000-0000-000000000000'),
  request_id uuid NOT NULL CHECK(request_id<>'00000000-0000-0000-0000-000000000000'),
  execution_id uuid NOT NULL CHECK(execution_id<>'00000000-0000-0000-0000-000000000000'),
  attempt_id uuid NOT NULL CHECK(attempt_id<>'00000000-0000-0000-0000-000000000000'),
  record_kind text NOT NULL CHECK(record_kind IN ('success_witness','attempt_observation')),
  operation text NOT NULL DEFAULT 'escalation_policy.delete' CHECK(operation='escalation_policy.delete'),
  root_type text NOT NULL DEFAULT 'escalation_policy' CHECK(root_type='escalation_policy'),
  root_id uuid CHECK(root_id<>'00000000-0000-0000-0000-000000000000'),
  target_organization_id uuid CHECK(target_organization_id<>'00000000-0000-0000-0000-000000000000'),
  target_org_resolution text NOT NULL,
  effects_version smallint NOT NULL DEFAULT 1 CHECK(effects_version=1),
  effects jsonb NOT NULL DEFAULT '[]'::jsonb,
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
  occurred_at timestamptz NOT NULL CHECK(isfinite(occurred_at) AND extract(year FROM occurred_at) BETWEEN 1 AND 9999),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(recorded_at)),
  CHECK (escalation_policy_delete_effects_valid(effects,root_id,target_organization_id)),
  CHECK (record_kind='success_witness' OR effects='[]'::jsonb),
  CHECK (((root_id IS NULL AND target_organization_id IS NULL AND target_org_resolution='unknown')
    OR (root_id IS NOT NULL AND target_organization_id IS NOT NULL AND (
      (target_org_resolution='known_normal' AND target_organization_id<>'296e2656-7221-53fe-bd0a-832d24ccfd03')
      ))) IS TRUE),
  CHECK (((record_kind='success_witness' AND outcome='committed' AND reason_code='deleted' AND root_id IS NOT NULL AND provenance='EXPLICIT' AND deletion_mechanism='explicit_sql' AND cause='explicit_target')
    OR (record_kind='attempt_observation' AND provenance IS NULL AND deletion_mechanism IS NULL AND cause IS NULL AND (
      (outcome='denied' AND reason_code='authority_denied')
      OR (outcome='validation_failed' AND reason_code IN ('invalid_fields','target_unavailable','target_in_use'))
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
      AND (authority_role='platform_admin' OR (authority_role='org_admin' AND home_organization_id=target_organization_id)))) IS TRUE)
);
CREATE UNIQUE INDEX escalation_policy_delete_success_target ON escalation_policy_delete_audit_events(attempt_id,root_id) WHERE record_kind='success_witness';
CREATE INDEX escalation_policy_delete_correlation ON escalation_policy_delete_audit_events(request_id,execution_id,attempt_id);
CREATE INDEX escalation_policy_delete_root ON escalation_policy_delete_audit_events(root_id,occurred_at,event_id);
CREATE INDEX escalation_policy_delete_org ON escalation_policy_delete_audit_events(target_organization_id,occurred_at,event_id);
CREATE INDEX escalation_policy_delete_actor ON escalation_policy_delete_audit_events(actor_id,occurred_at,event_id);
CREATE FUNCTION escalation_policy_delete_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='escalation_policy.delete audit is append-only';
END;
$$;
CREATE TRIGGER escalation_policy_delete_no_change BEFORE UPDATE OR DELETE ON escalation_policy_delete_audit_events
FOR EACH ROW EXECUTE FUNCTION escalation_policy_delete_append_only();
CREATE TRIGGER escalation_policy_delete_no_truncate BEFORE TRUNCATE ON escalation_policy_delete_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION escalation_policy_delete_append_only();
REVOKE ALL ON escalation_policy_delete_audit_events FROM PUBLIC;
REVOKE ALL ON FUNCTION escalation_policy_delete_append_only() FROM PUBLIC;

REVOKE ALL ON FUNCTION escalation_policy_delete_effects_valid(jsonb,uuid,uuid) FROM PUBLIC;

-- +migrate Down
DO $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='escalation_policy.delete audit downgrade refused: preserve audit history';
END;
$$;
