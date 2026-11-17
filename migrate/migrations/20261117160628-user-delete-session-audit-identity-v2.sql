-- +migrate Up
-- Session snapshot v2 only. Root/header v1 and all other resources are unchanged.
-- Frozen v1 functions remain available for historical reads. No history UPDATE.
ALTER FUNCTION user_delete_snapshot_valid(jsonb,text) RENAME TO user_delete_snapshot_v1_valid;
CREATE FUNCTION user_delete_snapshot_valid(v jsonb,typ text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
BEGIN
 IF typ IS DISTINCT FROM 'user_session' OR NOT (v ? 'version') THEN
  RETURN public.user_delete_snapshot_v1_valid(v,typ);
 END IF;
 RETURN (jsonb_typeof(v)='object' AND (SELECT count(*) FROM jsonb_object_keys(v))=4
  AND v ?& ARRAY['version','audit_resource_id','user_id','row_version']
  AND jsonb_typeof(v->'version')='number' AND v->>'version'='2'
  AND public.user_delete_scalar_valid(v->'audit_resource_id','u') IS TRUE
  AND public.user_delete_scalar_valid(v->'user_id','u') IS TRUE
  AND public.user_delete_scalar_valid(v->'row_version','x') IS TRUE) IS TRUE;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;

ALTER FUNCTION user_delete_effect_valid(jsonb) RENAME TO user_delete_effect_v1_valid;
CREATE FUNCTION user_delete_effect_valid(p jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE allowed text[]=ARRAY['effect_id','resource_type','resource_key','transition_slot','trigger_user_id','target_organization_id','org_resolution','change','provenance','deletion_mechanism','before','after'];
BEGIN
 IF p->>'resource_type' IS DISTINCT FROM 'user_session' OR NOT (p->'before' ? 'version') THEN
  RETURN public.user_delete_effect_v1_valid(p);
 END IF;
 RETURN (jsonb_typeof(p)='object' AND p ?& allowed
  AND (SELECT count(*) FROM jsonb_object_keys(p))=cardinality(allowed) AND octet_length(p::text)<=4096
  AND public.user_delete_scalar_valid(p->'effect_id','u') IS TRUE
  AND public.user_delete_scalar_valid(p->'trigger_user_id','u') IS TRUE
  AND public.user_delete_scalar_valid(p->'target_organization_id','U') IS TRUE
  AND public.user_delete_org_valid((p->>'target_organization_id')::uuid,p->>'org_resolution') IS TRUE
  AND public.user_delete_snapshot_valid(p->'before','user_session') IS TRUE
  AND jsonb_typeof(p->'resource_key')='string'
  AND p->>'resource_key'=p->'before'->>'audit_resource_id'
  AND p->>'transition_slot'='row' AND p->'after'='null'::jsonb
  AND p->>'change'='deleted' AND p->>'provenance'='IMPLICIT_FK_CASCADE'
  AND p->>'deletion_mechanism'='fk_cascade') IS TRUE;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;

-- Existing CHECK constraints bind function OIDs, so explicitly rebind this one
-- to the version-aware reader. It still validates every historical row.
ALTER TABLE user_delete_audit_effects DROP CONSTRAINT user_delete_effect_closed,
 ADD CONSTRAINT user_delete_effect_closed CHECK((public.user_delete_effect_valid(payload) IS TRUE
 AND payload->>'effect_id'=effect_id::text AND payload->>'resource_type'=resource_type
 AND payload->>'resource_key'=resource_key AND payload->>'transition_slot'=transition_slot) IS TRUE);

-- New writes cannot replay the credential-bearing v1 Session contract. A UUID
-- merely placed under the safe field is insufficient: require this transaction's
-- capture binding and prove the bound physical Session has actually disappeared.
CREATE FUNCTION user_delete_session_write_check() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.resource_type<>'user_session' THEN RETURN NEW;END IF;
 IF public.user_delete_effect_valid(NEW.payload) IS NOT TRUE
  OR NEW.payload->'before'->'version' IS DISTINCT FROM '2'::jsonb
  OR to_regclass('pg_temp.sd8_user_session_identity') IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Invalid user.delete Session identity';
 END IF;
 IF NOT EXISTS(SELECT FROM pg_temp.sd8_user_session_identity i
 JOIN public.user_delete_audit_events e ON e.event_id=i.event_id AND e.root_id=i.user_id AND e.root_ordinal=i.root_ordinal
 WHERE i.event_id=NEW.event_id AND i.audit_resource_id::text=NEW.resource_key
 AND NEW.payload->'before'->>'audit_resource_id'=i.audit_resource_id::text
 AND NEW.payload->'before'->>'user_id'=i.user_id::text
 AND NEW.payload->>'trigger_user_id'=i.user_id::text
 AND (NEW.payload->'before'->>'row_version')::bigint=i.row_version
 AND i.audit_resource_id<>i.session_id
 AND NOT EXISTS(SELECT FROM public.auth_user_sessions s WHERE s.id=i.session_id OR s.audit_resource_id=i.audit_resource_id)) THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Invalid user.delete Session binding';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER user_delete_session_write_check BEFORE INSERT ON user_delete_audit_effects
 FOR EACH ROW EXECUTE FUNCTION user_delete_session_write_check();
REVOKE ALL ON FUNCTION user_delete_snapshot_valid(jsonb,text),user_delete_effect_valid(jsonb),user_delete_session_write_check() FROM PUBLIC;

-- +migrate Down
DO $$ BEGIN RAISE EXCEPTION 'user.delete Session identity v2 is forward only'; END $$;
