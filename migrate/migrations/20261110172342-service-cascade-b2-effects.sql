-- +migrate Up

ALTER TABLE integration_keys ADD COLUMN audit_resource_id uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE integration_keys ADD CONSTRAINT integration_keys_audit_resource_identity CHECK (
  audit_resource_id<>'00000000-0000-0000-0000-000000000000' AND audit_resource_id<>id);
CREATE UNIQUE INDEX integration_keys_audit_resource_id ON integration_keys(audit_resource_id);
CREATE FUNCTION integration_key_audit_identity_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF NEW.audit_resource_id IS DISTINCT FROM OLD.audit_resource_id THEN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='integration key audit identity is immutable';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER integration_key_audit_identity_no_change BEFORE UPDATE ON integration_keys
FOR EACH ROW EXECUTE FUNCTION integration_key_audit_identity_immutable();

CREATE FUNCTION service_delete_effects_valid(effects jsonb, org_id uuid) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE
  e jsonb; eid uuid; rid uuid; uid uuid; oid uuid; target uuid; nid bigint;
  k text; previous_key text := ''; r text; field text;
BEGIN
  IF jsonb_typeof(effects)<>'array' OR jsonb_array_length(effects)>16384 OR octet_length(effects::text)>8388608 THEN RETURN false; END IF;
  FOR e IN SELECT value FROM jsonb_array_elements(effects) LOOP
    IF jsonb_typeof(e)<>'object' THEN RETURN false; END IF;
    IF NOT e ?& ARRAY['effect_id','resource_type','resource_uuid','resource_numeric_id','owner_user_id','owner_organization_id','owner_org_resolution','target_organization_id','relation','change','provenance','deletion_mechanism','cause']
      OR (SELECT count(*) FROM jsonb_object_keys(e))<>13 THEN RETURN false; END IF;
    FOREACH field IN ARRAY ARRAY['effect_id','resource_type','owner_org_resolution','target_organization_id','relation','change','provenance','deletion_mechanism','cause'] LOOP
      IF jsonb_typeof(e->field)<>'string' THEN RETURN false; END IF;
    END LOOP;
    eid:=(e->>'effect_id')::uuid; target:=(e->>'target_organization_id')::uuid;
    IF eid='00000000-0000-0000-0000-000000000000' OR eid::text<>e->>'effect_id'
      OR target='00000000-0000-0000-0000-000000000000' OR target::text<>e->>'target_organization_id'
      OR target IS DISTINCT FROM org_id THEN RETURN false; END IF;
    IF NOT ((e->>'provenance'='CASCADE' AND e->>'deletion_mechanism'='fk_cascade' AND e->>'cause'='service_delete')
      OR (e->>'provenance'='EXPLICIT' AND ((e->>'deletion_mechanism'='explicit_sql' AND e->>'cause'='explicit_target')
        OR (e->>'deletion_mechanism'='fk_cascade' AND e->>'cause'='service_delete')))) THEN RETURN false; END IF;
    rid:=NULL; nid:=NULL; uid:=NULL; oid:=NULL;
    IF e->>'resource_type'='integration_key' THEN
      IF jsonb_typeof(e->'resource_uuid')<>'string' OR e->'resource_numeric_id'<>'null'::jsonb THEN RETURN false; END IF;
      rid:=(e->>'resource_uuid')::uuid;
      IF rid='00000000-0000-0000-0000-000000000000' OR rid::text<>e->>'resource_uuid'
        OR e->>'relation'<>'service.integration_key' OR e->>'change'<>'deleted' THEN RETURN false; END IF;
      k:='integration_key/'||rid::text||'/'||(e->>'relation');
    ELSIF e->>'resource_type' IN ('alert','service_favorite') THEN
      IF e->'resource_uuid'<>'null'::jsonb OR jsonb_typeof(e->'resource_numeric_id')<>'number'
        OR (e->>'resource_numeric_id')!~'^[1-9][0-9]*$' THEN RETURN false; END IF;
      nid:=(e->>'resource_numeric_id')::bigint;
      IF nid<=0 THEN RETURN false; END IF;
      IF e->>'resource_type'='alert' THEN
        IF e->>'relation'<>'service.alert' OR e->>'change'<>'deleted' THEN RETURN false; END IF;
      ELSE
        IF e->>'relation'<>'service.favorite' OR e->>'change'<>'relationship_removed' OR e->>'provenance'<>'CASCADE' THEN RETURN false; END IF;
      END IF;
      k:=(e->>'resource_type')||'/'||lpad(nid::text,20,'0')||'/'||(e->>'relation');
    ELSE RETURN false; END IF;
    r:=e->>'owner_org_resolution';
    IF e->>'resource_type'<>'service_favorite' THEN
      IF e->'owner_user_id'<>'null'::jsonb OR e->'owner_organization_id'<>'null'::jsonb OR r<>'not_applicable' THEN RETURN false; END IF;
    ELSE
      IF jsonb_typeof(e->'owner_user_id')<>'string' THEN RETURN false; END IF;
      uid:=(e->>'owner_user_id')::uuid;
      IF uid='00000000-0000-0000-0000-000000000000' OR uid::text<>e->>'owner_user_id' THEN RETURN false; END IF;
      IF jsonb_typeof(e->'owner_organization_id')='string' THEN
        oid:=(e->>'owner_organization_id')::uuid;
        IF oid='00000000-0000-0000-0000-000000000000' OR oid::text<>e->>'owner_organization_id' THEN RETURN false; END IF;
      ELSIF e->'owner_organization_id'<>'null'::jsonb THEN RETURN false; END IF;
      IF NOT ((r='unknown' AND oid IS NULL)
        OR (r='known_normal' AND oid IS NOT NULL AND oid<>'296e2656-7221-53fe-bd0a-832d24ccfd03')
        OR (r='known_default' AND oid='296e2656-7221-53fe-bd0a-832d24ccfd03')) IS TRUE THEN RETURN false; END IF;
    END IF;
    IF (k COLLATE "C")<=(previous_key COLLATE "C") THEN RETURN false; END IF;
    previous_key:=k;
  END LOOP;
  RETURN (SELECT count(*)=count(DISTINCT value->>'effect_id') FROM jsonb_array_elements(effects));
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END;
$$;

-- Nullable columns preserve historical rows without inventing captured effects.
ALTER TABLE service_delete_audit_events ADD COLUMN effects_version smallint;
ALTER TABLE service_delete_audit_events ADD COLUMN execution_id uuid;
ALTER TABLE service_delete_audit_events ADD COLUMN effects jsonb;
ALTER TABLE service_delete_audit_events ADD CONSTRAINT service_delete_effects_envelope CHECK (
  ((effects_version IS NULL AND execution_id IS NULL AND effects IS NULL)
    OR (effects_version=1 AND execution_id IS NOT NULL AND execution_id<>'00000000-0000-0000-0000-000000000000'
      AND effects IS NOT NULL AND (outcome='committed' OR effects='[]'::jsonb)
      AND public.service_delete_effects_valid(effects,target_organization_id))) IS TRUE);
CREATE FUNCTION service_delete_new_envelope() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF NEW.effects_version IS DISTINCT FROM 1 OR NEW.execution_id IS NULL OR NEW.effects IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='service.delete requires a complete effects envelope';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER service_delete_require_envelope BEFORE INSERT ON service_delete_audit_events
FOR EACH ROW EXECUTE FUNCTION service_delete_new_envelope();
CREATE INDEX service_delete_correlation ON service_delete_audit_events(request_id,execution_id,attempt_id);
CREATE INDEX service_delete_effects ON service_delete_audit_events USING gin(effects jsonb_path_ops)
WHERE outcome='committed' AND effects_version=1;
REVOKE ALL ON FUNCTION integration_key_audit_identity_immutable() FROM PUBLIC;
REVOKE ALL ON FUNCTION service_delete_effects_valid(jsonb,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION service_delete_new_envelope() FROM PUBLIC;

-- +migrate Down
DO $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='service.delete B2 downgrade refused: preserve history and key identity';
END;
$$;
