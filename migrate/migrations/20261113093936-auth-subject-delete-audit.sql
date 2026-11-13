-- +migrate Up
-- D09-SD9-AUTHSUBJECT-IMPL1: typed explicit deletion witnesses, no backfill.
CREATE FUNCTION auth_subject_delete_event_valid(h jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE k text; b jsonb; r text; success boolean; home text;
BEGIN
 IF jsonb_typeof(h) IS DISTINCT FROM 'object' OR octet_length(h::text)>4096 THEN RETURN false; END IF;
 IF (h->>'schema_version'='1' AND h->>'operation'='auth_subject.delete' AND h->>'root_type'='auth_subject') IS NOT TRUE THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['event_id','request_id','execution_id','attempt_id'] LOOP
  IF (jsonb_typeof(h->k)='string' AND (h->>k)::uuid::text=h->>k AND (h->>k)::uuid<>'00000000-0000-0000-0000-000000000000') IS NOT TRUE THEN RETURN false;END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['actor_id','home_organization_id','target_organization_id'] LOOP
  IF h->k IS NULL THEN RETURN false; END IF;
  IF h->k<>'null' THEN
   IF (jsonb_typeof(h->k)='string' AND (h->>k)::uuid::text=h->>k AND (h->>k)::uuid<>'00000000-0000-0000-0000-000000000000') IS NOT TRUE THEN RETURN false; END IF;
  END IF;
 END LOOP;
 -- Real owner/CM UUIDs retain the business schema's complete identity domain.
 FOREACH k IN ARRAY ARRAY['root_owner_user_id','parent_cm_id'] LOOP
  IF h->k IS NULL THEN RETURN false; END IF;
  IF h->k<>'null' AND (jsonb_typeof(h->k)='string' AND (h->>k)::uuid::text=h->>k) IS NOT TRUE THEN RETURN false; END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['occurred_at','recorded_at'] LOOP
  IF (isfinite((h->>k)::timestamptz) AND extract(year FROM (h->>k)::timestamptz) BETWEEN 1 AND 9999) IS NOT TRUE THEN RETURN false;END IF;
 END LOOP;
 IF public.user_delete_org_valid((h->>'target_organization_id')::uuid,h->>'target_org_resolution') IS NOT TRUE THEN RETURN false;END IF;
 IF h->'root_id'='null' THEN
  IF (h->'root_owner_user_id'='null' AND h->'parent_cm_id'='null' AND h->'target_organization_id'='null' AND h->>'target_org_resolution'='unknown') IS NOT TRUE THEN RETURN false;END IF;
 ELSE
  r:=h->>'root_id';
  IF (jsonb_typeof(h->'root_id')='string' AND r::bigint::text=r AND h->'root_owner_user_id'<>'null') IS NOT TRUE THEN RETURN false;END IF;
 END IF;
 success:=h->>'record_kind'='success_witness';home:=h->>'home_organization_id';
 CASE h->>'actor_kind'
 WHEN 'human' THEN
  IF (h->'actor_id'<>'null' AND h->'home_organization_id'<>'null' AND h->>'authority_source'='current_local_user_organization_at_admission') IS NOT TRUE THEN RETURN false;END IF;
  IF home='296e2656-7221-53fe-bd0a-832d24ccfd03' THEN
   IF (h->>'organization_role'='NONE' AND h->>'authority_role' IN ('platform_admin','none')) IS NOT TRUE THEN RETURN false;END IF;
  ELSE
   IF (h->>'organization_role' IN ('ORG_ADMIN','ORG_MEMBER') AND (h->>'authority_role'='platform_admin' OR h->>'authority_role'='org_admin' AND h->>'organization_role'='ORG_ADMIN' OR h->>'authority_role'='org_member' AND h->>'organization_role'='ORG_MEMBER')) IS NOT TRUE THEN RETURN false;END IF;
  END IF;
  IF success AND (h->>'authority_role'='platform_admin' AND (home<>'296e2656-7221-53fe-bd0a-832d24ccfd03' OR h->>'target_org_resolution'='known_normal')) IS NOT TRUE THEN RETURN false;END IF;
 WHEN 'internal_system' THEN
  IF (h->'actor_id'='null' AND h->'home_organization_id'='null' AND h->>'authority_source'='trusted_internal_system' AND h->>'authority_role'='internal_system' AND h->>'organization_role'='unknown') IS NOT TRUE THEN RETURN false;END IF;
 WHEN 'unknown' THEN
  IF (NOT success AND h->'actor_id'='null' AND h->'home_organization_id'='null' AND h->>'authority_source'='unknown' AND h->>'authority_role'='unknown' AND h->>'organization_role'='unknown') IS NOT TRUE THEN RETURN false;END IF;
 ELSE RETURN false;
 END CASE;
 b:=h->'before_context';
 IF success THEN
  IF (h->'root_id'<>'null' AND h->>'outcome'='committed' AND h->>'reason_code'='deleted' AND h->>'provenance'='EXPLICIT' AND h->>'deletion_mechanism'='explicit_sql' AND h->>'cause'='explicit_target') IS NOT TRUE THEN RETURN false;END IF;
  IF jsonb_typeof(b) IS DISTINCT FROM 'object' OR NOT b ?& ARRAY['version','id','user_id','cm_id','row_version'] OR (SELECT count(*) FROM jsonb_object_keys(b))<>5 THEN RETURN false;END IF;
  IF (b->'version'='1' AND jsonb_typeof(b->'id')='string' AND (b->>'id')::bigint::text=b->>'id' AND b->'id'=h->'root_id' AND b->'user_id'=h->'root_owner_user_id' AND b->'cm_id'=h->'parent_cm_id' AND jsonb_typeof(b->'row_version')='number' AND (b->>'row_version')::bigint BETWEEN 1 AND 4294967295 AND (b->>'row_version')::bigint::text=b->>'row_version') IS NOT TRUE THEN RETURN false;END IF;
 ELSE
  IF (h->>'record_kind'='attempt_observation' AND b='null' AND h->>'provenance'='' AND h->>'deletion_mechanism'='' AND h->>'cause'='') IS NOT TRUE THEN RETURN false;END IF;
  IF ((h->>'outcome'='denied' AND h->>'reason_code' IN ('authority_denied','guard_denied')) OR (h->>'outcome'='validation_failed' AND h->>'reason_code'='invalid_input') OR (h->>'outcome'='tx_failed' AND h->>'reason_code' IN ('begin_failed','capture_failed','delete_failed','receipt_invalid','postcheck_failed','audit_write_failed','commit_rejected','transaction_ownership_unavailable','panic')) OR (h->>'outcome'='commit_unknown' AND h->>'reason_code'='commit_unconfirmed') OR (h->>'outcome'='rollback_unconfirmed' AND h->>'reason_code'='rollback_unconfirmed')) IS NOT TRUE THEN RETURN false;END IF;
 END IF;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
CREATE TABLE auth_subject_delete_audit_events (
 schema_version smallint NOT NULL DEFAULT 1,
 event_id uuid PRIMARY KEY,request_id uuid NOT NULL,execution_id uuid NOT NULL,attempt_id uuid NOT NULL,
 record_kind text NOT NULL,operation text NOT NULL DEFAULT 'auth_subject.delete',root_type text NOT NULL DEFAULT 'auth_subject',
 root_id bigint,root_owner_user_id uuid,parent_cm_id uuid,
 actor_kind text NOT NULL,actor_id uuid,home_organization_id uuid,authority_source text NOT NULL,authority_role text NOT NULL,organization_role text NOT NULL,
 target_organization_id uuid,target_org_resolution text NOT NULL,before_context jsonb NOT NULL DEFAULT 'null',
 provenance text NOT NULL DEFAULT '',deletion_mechanism text NOT NULL DEFAULT '',cause text NOT NULL DEFAULT '',
 outcome text NOT NULL,reason_code text NOT NULL,occurred_at timestamptz NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CONSTRAINT auth_subject_delete_closed CHECK (public.auth_subject_delete_event_valid(jsonb_build_object('schema_version',schema_version,'event_id',event_id,'request_id',request_id,'execution_id',execution_id,'attempt_id',attempt_id,'record_kind',record_kind,'operation',operation,'root_type',root_type,'root_id',root_id::text,'root_owner_user_id',root_owner_user_id,'parent_cm_id',parent_cm_id,'actor_kind',actor_kind,'actor_id',actor_id,'home_organization_id',home_organization_id,'authority_source',authority_source,'authority_role',authority_role,'organization_role',organization_role,'target_organization_id',target_organization_id,'target_org_resolution',target_org_resolution,'before_context',before_context,'provenance',provenance,'deletion_mechanism',deletion_mechanism,'cause',cause,'outcome',outcome,'reason_code',reason_code,'occurred_at',occurred_at,'recorded_at',recorded_at)) IS TRUE)
);
CREATE UNIQUE INDEX auth_subject_delete_success ON auth_subject_delete_audit_events(attempt_id,root_id) WHERE record_kind='success_witness';
CREATE UNIQUE INDEX auth_subject_delete_observation ON auth_subject_delete_audit_events(attempt_id) WHERE record_kind='attempt_observation';
CREATE INDEX auth_subject_delete_root_history ON auth_subject_delete_audit_events(root_id,occurred_at,event_id) WHERE record_kind='success_witness';
CREATE INDEX auth_subject_delete_attempt_history ON auth_subject_delete_audit_events(attempt_id,event_id);
CREATE FUNCTION auth_subject_delete_append_only() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='auth_subject.delete audit is append only'; END;
$$;
CREATE TRIGGER auth_subject_delete_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON auth_subject_delete_audit_events FOR EACH STATEMENT EXECUTE FUNCTION auth_subject_delete_append_only();
REVOKE ALL ON FUNCTION auth_subject_delete_event_valid(jsonb),auth_subject_delete_append_only() FROM PUBLIC;
