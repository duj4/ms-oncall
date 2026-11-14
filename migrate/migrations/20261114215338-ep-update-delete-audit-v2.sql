-- +migrate Up

-- D09-SD10 U01/U02. Existing v1 storage fixes both the root operation and its
-- effects to EP deletion. v2 reuses the append-only table without inventing a
-- deleted parent for a surviving Step. No historical rows or v1 function change.
CREATE FUNCTION escalation_policy_update_delete_effects_valid(effects jsonb,root uuid,org uuid,operation text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE f jsonb; k text; v jsonb; expected text[];
BEGIN
 IF operation NOT IN ('updateEscalationPolicy','updateEscalationPolicyStep') OR effects IS NULL OR jsonb_typeof(effects)<>'array' THEN RETURN false; END IF;
 IF jsonb_array_length(effects)>16384 OR octet_length(effects::text)>8388608 THEN RETURN false; END IF;
 IF (SELECT count(DISTINCT (value->>'effect_id')::uuid) FROM jsonb_array_elements(effects))<>jsonb_array_length(effects) THEN RETURN false; END IF;
 IF (SELECT count(DISTINCT ROW(value->>'resource_type',(value->>'resource_uuid')::uuid)) FROM jsonb_array_elements(effects))<>jsonb_array_length(effects) THEN RETURN false; END IF;
 IF operation='updateEscalationPolicy' AND EXISTS(
  (SELECT (value->>'parent_step_id')::uuid FROM jsonb_array_elements(effects) WHERE value->>'resource_type'='escalation_policy_action')
  EXCEPT
  (SELECT (value->>'resource_uuid')::uuid FROM jsonb_array_elements(effects) WHERE value->>'resource_type'='escalation_policy_step')
 ) THEN RETURN false; END IF;
 FOR f IN SELECT value FROM jsonb_array_elements(effects) LOOP
  IF jsonb_typeof(f)<>'object' THEN RETURN false; END IF;
  CASE f->>'resource_type'
   WHEN 'escalation_policy_step' THEN expected=ARRAY['effect_id','resource_type','root_id','target_organization_id','relation','change','provenance','deletion_mechanism','cause','resource_uuid','step_number']::text[];
   WHEN 'escalation_policy_action' THEN expected=ARRAY['effect_id','resource_type','root_id','target_organization_id','relation','change','provenance','deletion_mechanism','cause','resource_uuid','parent_step_id','target_kind','target_id']::text[];
   ELSE RETURN false;
  END CASE;
  IF NOT (f ?& expected) OR (SELECT count(*) FROM jsonb_object_keys(f))<>cardinality(expected) THEN RETURN false; END IF;
  FOR k,v IN SELECT * FROM jsonb_each(f) LOOP
   IF k='step_number' THEN
    IF jsonb_typeof(v)<>'number' OR v::text !~ '^[0-9]+$' THEN RETURN false; END IF;
   ELSIF jsonb_typeof(v)<>'string' THEN RETURN false;
   END IF;
   IF k IN ('effect_id','root_id','target_organization_id','resource_uuid','parent_step_id','target_id') THEN
    IF (f->>k)::uuid='00000000-0000-0000-0000-000000000000' THEN RETURN false; END IF;
   END IF;
  END LOOP;
  IF ((f->>'root_id')::uuid=root AND (f->>'target_organization_id')::uuid=org AND f->>'change'='deleted') IS NOT TRUE THEN RETURN false; END IF;
  CASE f->>'resource_type'
   WHEN 'escalation_policy_step' THEN
    IF (operation='updateEscalationPolicy' AND f->>'relation'='escalation_policy.step' AND (f->>'step_number')::integer>=0
     AND f->>'provenance'='EXPLICIT' AND f->>'deletion_mechanism'='explicit_sql' AND f->>'cause'='update_induced') IS NOT TRUE THEN RETURN false; END IF;
   WHEN 'escalation_policy_action' THEN
    IF (f->>'relation'='escalation_policy.step.action' AND f->>'target_kind' IN ('user','schedule','rotation','notification_channel')) IS NOT TRUE THEN RETURN false; END IF;
    IF ((operation='updateEscalationPolicy' AND f->>'provenance'='CASCADE' AND f->>'deletion_mechanism'='fk_cascade' AND f->>'cause'='step_delete')
      OR (operation='updateEscalationPolicyStep' AND (f->>'parent_step_id')::uuid=root AND f->>'provenance'='EXPLICIT' AND f->>'deletion_mechanism'='explicit_sql' AND f->>'cause'='update_induced')) IS NOT TRUE THEN RETURN false; END IF;
  END CASE;
 END LOOP;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;

ALTER TABLE escalation_policy_delete_audit_events
 ADD COLUMN parent_policy_id uuid CHECK(parent_policy_id<>'00000000-0000-0000-0000-000000000000'),
 DROP CONSTRAINT escalation_policy_delete_audit_events_schema_version_check,
 DROP CONSTRAINT escalation_policy_delete_audit_events_effects_version_check,
 DROP CONSTRAINT escalation_policy_delete_audit_events_operation_check,
 DROP CONSTRAINT escalation_policy_delete_audit_events_root_type_check,
 DROP CONSTRAINT escalation_policy_delete_audit_events_check,
 DROP CONSTRAINT escalation_policy_delete_audit_events_check3,
 ADD CONSTRAINT escalation_policy_delete_audit_events_schema_version_check CHECK(schema_version IN (1,2)),
 ADD CONSTRAINT escalation_policy_delete_audit_events_effects_version_check CHECK(effects_version=schema_version),
 ADD CONSTRAINT escalation_policy_delete_audit_events_operation_check CHECK(((schema_version=1 AND operation='escalation_policy.delete' AND root_type='escalation_policy' AND parent_policy_id IS NULL)
  OR (schema_version=2 AND operation='updateEscalationPolicy' AND root_type='escalation_policy' AND parent_policy_id IS NULL)
  OR (schema_version=2 AND operation='updateEscalationPolicyStep' AND root_type='escalation_policy_step' AND ((root_id IS NULL AND parent_policy_id IS NULL) OR (root_id IS NOT NULL AND parent_policy_id IS NOT NULL)))) IS TRUE),
 ADD CONSTRAINT escalation_policy_delete_audit_events_check CHECK((CASE schema_version WHEN 1 THEN escalation_policy_delete_effects_valid(effects,root_id,target_organization_id) WHEN 2 THEN escalation_policy_update_delete_effects_valid(effects,root_id,target_organization_id,operation) ELSE false END) IS TRUE),
 ADD CONSTRAINT escalation_policy_delete_audit_events_check3 CHECK(((record_kind='success_witness' AND outcome='committed' AND root_id IS NOT NULL AND provenance='EXPLICIT' AND deletion_mechanism='explicit_sql'
   AND ((schema_version=1 AND reason_code='deleted' AND cause='explicit_target') OR (schema_version=2 AND reason_code='children_deleted' AND cause='update_induced' AND jsonb_array_length(effects)>0)))
  OR (record_kind='attempt_observation' AND provenance IS NULL AND deletion_mechanism IS NULL AND cause IS NULL AND (
   (outcome='denied' AND reason_code='authority_denied')
   OR (outcome='validation_failed' AND reason_code IN ('invalid_fields','target_unavailable','target_in_use'))
   OR (outcome='tx_failed' AND reason_code IN ('begin_failed','write_failed','audit_write_failed','commit_rejected'))
   OR (outcome='commit_unknown' AND reason_code='commit_unconfirmed')
   OR (outcome='rollback_unconfirmed' AND reason_code='rollback_unconfirmed')))) IS TRUE);

REVOKE ALL ON FUNCTION escalation_policy_update_delete_effects_valid(jsonb,uuid,uuid,text) FROM PUBLIC;

-- +migrate Down
DO $$
BEGIN
 RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='EP update deletion audit downgrade refused: preserve audit history';
END;
$$;
