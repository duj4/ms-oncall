-- +migrate Up

-- U03: versioned extension of existing append-only Schedule/Rotation storage.
-- v1 Root Delete records and validators remain intact. No historical UPDATE.
CREATE FUNCTION schedule_target_update_delete_effects_valid(effects jsonb,root uuid,org uuid) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE f jsonb; d jsonb; k text; v jsonb;
 expected text[]=ARRAY['effect_id','resource_type','root_id','target_organization_id','relation','change','provenance','deletion_mechanism','cause','resource_uuid','rule_deletion'];
BEGIN
 IF effects IS NULL OR jsonb_typeof(effects)<>'array' THEN RETURN false; END IF;
 IF jsonb_array_length(effects)>16384 OR octet_length(effects::text)>8388608 THEN RETURN false; END IF;
 IF (SELECT count(DISTINCT (value->>'effect_id')::uuid) FROM jsonb_array_elements(effects))<>jsonb_array_length(effects) THEN RETURN false; END IF;
 IF (SELECT count(DISTINCT (value->>'resource_uuid')::uuid) FROM jsonb_array_elements(effects))<>jsonb_array_length(effects) THEN RETURN false; END IF;
 IF (SELECT count(DISTINCT ROW(value->'rule_deletion'->>'target_kind',(value->'rule_deletion'->>'target_id')::uuid)) FROM jsonb_array_elements(effects))>1 THEN RETURN false; END IF;
 FOR f IN SELECT value FROM jsonb_array_elements(effects) LOOP
  IF jsonb_typeof(f)<>'object' OR NOT (f ?& expected) OR (SELECT count(*) FROM jsonb_object_keys(f))<>cardinality(expected) THEN RETURN false; END IF;
  FOR k,v IN SELECT * FROM jsonb_each(f) LOOP
   IF k='rule_deletion' THEN
    IF jsonb_typeof(v)<>'object' THEN RETURN false; END IF;
   ELSIF jsonb_typeof(v)<>'string' THEN RETURN false;
   END IF;
   IF k IN ('effect_id','root_id','target_organization_id','resource_uuid') THEN
    IF (f->>k)::uuid='00000000-0000-0000-0000-000000000000' THEN RETURN false; END IF;
   END IF;
  END LOOP;
  IF (f->>'resource_type'='schedule_rule' AND (f->>'root_id')::uuid=root AND (f->>'target_organization_id')::uuid=org
   AND f->>'relation'='schedule.schedule_rule' AND f->>'change'='deleted' AND f->>'provenance'='EXPLICIT'
   AND f->>'deletion_mechanism'='explicit_sql' AND f->>'cause'='update_induced') IS NOT TRUE THEN RETURN false; END IF;
  d=f->'rule_deletion';
  IF NOT (d ?& ARRAY['schedule_id','target_kind','target_id']) OR (SELECT count(*) FROM jsonb_object_keys(d))<>3 THEN RETURN false; END IF;
  FOR k,v IN SELECT * FROM jsonb_each(d) LOOP
   IF jsonb_typeof(v)<>'string' THEN RETURN false; END IF;
  END LOOP;
  IF ((d->>'schedule_id')::uuid=root AND d->>'target_kind' IN ('user','rotation')
   AND (d->>'target_id')::uuid<>'00000000-0000-0000-0000-000000000000') IS NOT TRUE THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;

ALTER TABLE schedule_rotation_delete_audit_events
 DROP CONSTRAINT schedule_rotation_delete_audit_events_schema_version_check,
 DROP CONSTRAINT schedule_rotation_delete_audit_events_effects_version_check,
 DROP CONSTRAINT schedule_rotation_delete_audit_events_check,
 DROP CONSTRAINT schedule_rotation_delete_audit_events_check1,
 DROP CONSTRAINT schedule_rotation_delete_audit_events_check4,
 ADD CONSTRAINT schedule_rotation_delete_audit_events_schema_version_check CHECK(schema_version IN (1,2)),
 ADD CONSTRAINT schedule_rotation_delete_audit_events_effects_version_check CHECK(effects_version=schema_version),
 ADD CONSTRAINT schedule_rotation_delete_audit_events_check CHECK(((schema_version=1 AND operation=root_type||'.delete')
  OR (schema_version=2 AND root_type='schedule' AND operation='updateScheduleTarget')) IS TRUE),
 ADD CONSTRAINT schedule_rotation_delete_audit_events_check1 CHECK((CASE schema_version
  WHEN 1 THEN schedule_rotation_delete_effects_valid(effects,before_state,root_id,target_organization_id,root_type,actor_kind='human')
  WHEN 2 THEN before_state='null'::jsonb AND schedule_target_update_delete_effects_valid(effects,root_id,target_organization_id)
  ELSE false END) IS TRUE),
 ADD CONSTRAINT schedule_rotation_delete_audit_events_check4 CHECK(((record_kind='success_witness' AND outcome='committed' AND root_id IS NOT NULL AND provenance='EXPLICIT' AND deletion_mechanism='explicit_sql'
  AND ((schema_version=1 AND reason_code='deleted' AND cause='explicit_target')
   OR (schema_version=2 AND reason_code='children_deleted' AND cause='update_induced' AND jsonb_array_length(effects)>0)))
  OR (record_kind='attempt_observation' AND provenance IS NULL AND deletion_mechanism IS NULL AND cause IS NULL AND (
   (outcome='denied' AND reason_code='authority_denied')
   OR (outcome='validation_failed' AND reason_code IN ('invalid_fields','target_unavailable','target_in_use'))
   OR (outcome='tx_failed' AND reason_code IN ('begin_failed','write_failed','audit_write_failed','commit_rejected'))
   OR (outcome='commit_unknown' AND reason_code='commit_unconfirmed')
   OR (outcome='rollback_unconfirmed' AND reason_code='rollback_unconfirmed')))) IS TRUE);

REVOKE ALL ON FUNCTION schedule_target_update_delete_effects_valid(jsonb,uuid,uuid) FROM PUBLIC;

-- +migrate Down
DO $$
BEGIN
 RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Schedule target update deletion audit downgrade refused: preserve audit history';
END;
$$;
