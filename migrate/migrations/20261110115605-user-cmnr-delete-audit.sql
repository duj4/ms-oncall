-- +migrate Up

-- D09-SD2 v1: closed historical identity snapshots, no live-resource FKs.
-- JSONB is bounded at 16384 effects / 8 MiB. Overflow aborts the deletion.
CREATE FUNCTION user_cmnr_delete_effects_valid(effects jsonb, owner_id uuid, org_id uuid, resolution text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE
  e jsonb; eid uuid; rid uuid; uid uuid; oid uuid; nid bigint;
  k text; previous_key text := ''; r text;
BEGIN
  IF jsonb_typeof(effects)<>'array' OR jsonb_array_length(effects)>16384 OR octet_length(effects::text)>8388608 THEN RETURN false; END IF;
  FOR e IN SELECT value FROM jsonb_array_elements(effects) LOOP
    IF jsonb_typeof(e)<>'object' THEN RETURN false; END IF;
    IF NOT e ?& ARRAY['effect_id','resource_type','resource_uuid','resource_numeric_id','owner_user_id','target_organization_id','org_resolution','relation','change','provenance']
      OR (SELECT count(*) FROM jsonb_object_keys(e))<>10 THEN RETURN false; END IF;
    IF jsonb_typeof(e->'effect_id')<>'string' OR jsonb_typeof(e->'owner_user_id')<>'string'
      OR jsonb_typeof(e->'resource_type')<>'string' OR jsonb_typeof(e->'org_resolution')<>'string'
      OR jsonb_typeof(e->'relation')<>'string' OR jsonb_typeof(e->'change')<>'string' OR jsonb_typeof(e->'provenance')<>'string' THEN RETURN false; END IF;
    eid:=(e->>'effect_id')::uuid; uid:=(e->>'owner_user_id')::uuid;
    IF eid='00000000-0000-0000-0000-000000000000' OR uid='00000000-0000-0000-0000-000000000000'
      OR eid::text<>e->>'effect_id' OR uid::text<>e->>'owner_user_id' THEN RETURN false; END IF;
    oid:=NULL; rid:=NULL; nid:=NULL;
    IF jsonb_typeof(e->'target_organization_id')='string' THEN
      oid:=(e->>'target_organization_id')::uuid;
      IF oid='00000000-0000-0000-0000-000000000000' OR oid::text<>e->>'target_organization_id' THEN RETURN false; END IF;
    ELSIF e->'target_organization_id'<>'null'::jsonb THEN RETURN false; END IF;
    r:=e->>'org_resolution';
    IF NOT ((r='unknown' AND oid IS NULL)
      OR (r='known_normal' AND oid IS NOT NULL AND oid<>'296e2656-7221-53fe-bd0a-832d24ccfd03')
      OR (r='known_default' AND oid='296e2656-7221-53fe-bd0a-832d24ccfd03')) IS TRUE THEN RETURN false; END IF;
    IF e->>'resource_type'='auth_subject' THEN
      IF e->'resource_uuid'<>'null'::jsonb OR jsonb_typeof(e->'resource_numeric_id')<>'number'
        OR (e->>'resource_numeric_id')!~'^[1-9][0-9]*$' THEN RETURN false; END IF;
      nid:=(e->>'resource_numeric_id')::bigint;
      IF nid<=0 OR e->>'relation'<>'contact_method.auth_subject' OR e->>'change'<>'deleted' OR e->>'provenance'<>'IMPLICIT_FK_CASCADE' THEN RETURN false; END IF;
      k:='auth_subject/'||lpad(nid::text,20,'0')||'/'||(e->>'relation');
    ELSE
      IF jsonb_typeof(e->'resource_uuid')<>'string' OR e->'resource_numeric_id'<>'null'::jsonb THEN RETURN false; END IF;
      rid:=(e->>'resource_uuid')::uuid;
      IF rid='00000000-0000-0000-0000-000000000000' OR rid::text<>e->>'resource_uuid' THEN RETURN false; END IF;
      IF e->>'resource_type'='notification_rule' THEN
        IF e->>'relation'<>'contact_method.notification_rule' OR e->>'change'<>'deleted' OR e->>'provenance'<>'IMPLICIT_FK_CASCADE'
          OR uid IS DISTINCT FROM owner_id OR oid IS DISTINCT FROM org_id OR r IS DISTINCT FROM resolution THEN RETURN false; END IF;
      ELSIF e->>'resource_type'='user_status_contact_setting' THEN
        IF e->>'relation'<>'user.alert_status_log_contact_method' OR e->>'change'<>'relationship_cleared' OR e->>'provenance'<>'IMPLICIT_FK_SET_NULL' OR rid<>uid THEN RETURN false; END IF;
      ELSE RETURN false; END IF;
      k:=(e->>'resource_type')||'/'||rid::text||'/'||(e->>'relation');
    END IF;
    -- Canonical order also rules out duplicate business identities.
    IF (k COLLATE "C")<=(previous_key COLLATE "C") THEN RETURN false; END IF;
    previous_key:=k;
  END LOOP;
  RETURN (SELECT count(*)=count(DISTINCT value->>'effect_id') FROM jsonb_array_elements(effects));
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END;
$$;

CREATE FUNCTION user_cmnr_delete_related_valid(related jsonb, own_id uuid) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE e jsonb; id uuid; previous_id uuid;
BEGIN
  IF jsonb_typeof(related)<>'array' OR jsonb_array_length(related)>50 THEN RETURN false; END IF;
  FOR e IN SELECT value FROM jsonb_array_elements(related) LOOP
    IF jsonb_typeof(e)<>'object' THEN RETURN false; END IF;
    IF NOT e ?& ARRAY['event_id','relation'] OR (SELECT count(*) FROM jsonb_object_keys(e))<>2
      OR jsonb_typeof(e->'event_id')<>'string' OR jsonb_typeof(e->'relation')<>'string' OR e->>'relation'<>'parent_cm' THEN RETURN false; END IF;
    id:=(e->>'event_id')::uuid;
    IF id='00000000-0000-0000-0000-000000000000' OR id=own_id OR id::text<>e->>'event_id' OR (previous_id IS NOT NULL AND id<=previous_id) THEN RETURN false; END IF;
    previous_id:=id;
  END LOOP;
  RETURN true;
EXCEPTION WHEN invalid_text_representation THEN RETURN false;
END;
$$;

CREATE TABLE user_cmnr_delete_audit_events (
  schema_version smallint NOT NULL DEFAULT 1 CHECK(schema_version=1),
  event_id uuid PRIMARY KEY CHECK(event_id<>'00000000-0000-0000-0000-000000000000'),
  request_id uuid NOT NULL CHECK(request_id<>'00000000-0000-0000-0000-000000000000'),
  execution_id uuid NOT NULL CHECK(execution_id<>'00000000-0000-0000-0000-000000000000'),
  attempt_id uuid NOT NULL CHECK(attempt_id<>'00000000-0000-0000-0000-000000000000'),
  record_kind text NOT NULL CHECK(record_kind IN ('success_witness','attempt_observation')),
  operation text NOT NULL CHECK(operation IN ('contact_method.delete','notification_rule.delete','cmnr.delete_attempt')),
  root_type text,
  root_id uuid CHECK(root_id<>'00000000-0000-0000-0000-000000000000'),
  root_owner_user_id uuid CHECK(root_owner_user_id<>'00000000-0000-0000-0000-000000000000'),
  target_organization_id uuid CHECK(target_organization_id<>'00000000-0000-0000-0000-000000000000'),
  target_org_resolution text NOT NULL,
  parent_cm_id uuid CHECK(parent_cm_id<>'00000000-0000-0000-0000-000000000000'),
  provenance text,
  deletion_mechanism text,
  cause_event_id uuid CHECK(cause_event_id<>'00000000-0000-0000-0000-000000000000'),
  actor_kind text NOT NULL CHECK(actor_kind IN ('human','internal_system','unknown')),
  actor_id uuid CHECK(actor_id<>'00000000-0000-0000-0000-000000000000'),
  represented_human_id uuid CHECK(represented_human_id IS NULL),
  home_organization_id uuid CHECK(home_organization_id<>'00000000-0000-0000-0000-000000000000'),
  authority_source text NOT NULL,
  authority_role text NOT NULL,
  organization_role text NOT NULL,
  effects jsonb NOT NULL DEFAULT '[]',
  related_explicit_events jsonb NOT NULL DEFAULT '[]',
  outcome text NOT NULL,
  reason_code text NOT NULL,
  occurred_at timestamptz NOT NULL CHECK(isfinite(occurred_at)),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(recorded_at)),
  CHECK (((target_org_resolution='unknown' AND target_organization_id IS NULL)
    OR (target_org_resolution='known_normal' AND target_organization_id IS NOT NULL AND target_organization_id<>'296e2656-7221-53fe-bd0a-832d24ccfd03')
    OR (target_org_resolution='known_default' AND target_organization_id='296e2656-7221-53fe-bd0a-832d24ccfd03')) IS TRUE),
  CHECK (((root_id IS NULL AND root_type IS NULL AND root_owner_user_id IS NULL AND parent_cm_id IS NULL AND target_org_resolution='unknown')
    OR (root_id IS NOT NULL AND root_owner_user_id IS NOT NULL AND (
      (root_type='contact_method' AND operation='contact_method.delete' AND parent_cm_id IS NULL)
      OR (root_type='notification_rule' AND operation='notification_rule.delete' AND parent_cm_id IS NOT NULL)))) IS TRUE),
  CHECK (operation<>'cmnr.delete_attempt' OR root_id IS NULL),
  CHECK (((record_kind='success_witness' AND outcome='committed' AND reason_code='deleted' AND root_id IS NOT NULL AND provenance='EXPLICIT'
      AND ((deletion_mechanism='explicit_sql' AND cause_event_id IS NULL)
        OR (root_type='notification_rule' AND deletion_mechanism='fk_cascade' AND cause_event_id IS NOT NULL AND cause_event_id<>event_id)))
    OR (record_kind='attempt_observation' AND provenance IS NULL AND deletion_mechanism IS NULL AND cause_event_id IS NULL
      AND effects='[]'::jsonb AND related_explicit_events='[]'::jsonb AND (
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
      AND (authority_role='platform_admin' OR (authority_role IN ('org_member','org_admin') AND actor_id=root_owner_user_id AND home_organization_id=target_organization_id)))) IS TRUE),
  CHECK (COALESCE(root_type='contact_method',false) OR (effects='[]'::jsonb AND related_explicit_events='[]'::jsonb)),
  CHECK (public.user_cmnr_delete_effects_valid(effects,root_owner_user_id,target_organization_id,target_org_resolution) IS TRUE),
  CHECK (public.user_cmnr_delete_related_valid(related_explicit_events,event_id) IS TRUE)
);

CREATE UNIQUE INDEX user_cmnr_delete_success_target ON user_cmnr_delete_audit_events(attempt_id,root_type,root_id) WHERE record_kind='success_witness';
CREATE INDEX user_cmnr_delete_correlation ON user_cmnr_delete_audit_events(request_id,execution_id,attempt_id);
CREATE INDEX user_cmnr_delete_attempt ON user_cmnr_delete_audit_events(attempt_id);
CREATE INDEX user_cmnr_delete_root ON user_cmnr_delete_audit_events(root_type,root_id,occurred_at,event_id);
CREATE INDEX user_cmnr_delete_org ON user_cmnr_delete_audit_events(target_organization_id,occurred_at,event_id);
CREATE INDEX user_cmnr_delete_actor ON user_cmnr_delete_audit_events(actor_id,occurred_at,event_id);
CREATE INDEX user_cmnr_delete_effects ON user_cmnr_delete_audit_events USING gin(effects jsonb_path_ops);

CREATE FUNCTION user_cmnr_delete_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='cmnr.delete audit history is append-only';
END;
$$;
CREATE TRIGGER user_cmnr_delete_no_rewrite BEFORE UPDATE OR DELETE OR TRUNCATE ON user_cmnr_delete_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION user_cmnr_delete_append_only();
REVOKE ALL ON user_cmnr_delete_audit_events FROM PUBLIC;
REVOKE ALL ON FUNCTION user_cmnr_delete_effects_valid(jsonb,uuid,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION user_cmnr_delete_related_valid(jsonb,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION user_cmnr_delete_append_only() FROM PUBLIC;

-- +migrate Down
DO $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='cmnr.delete audit downgrade refused: preserve audit history';
END;
$$;
