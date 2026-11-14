-- +migrate Up
-- D09-SD9-USERSESSION-IMPL1. Forward only. No historical revocations.
ALTER TABLE auth_user_sessions ADD COLUMN audit_resource_id uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE auth_user_sessions ADD CONSTRAINT auth_user_session_audit_identity UNIQUE(audit_resource_id);
ALTER TABLE auth_user_sessions ADD CONSTRAINT auth_user_session_audit_identity_nonzero CHECK(audit_resource_id<>'00000000-0000-0000-0000-000000000000');
CREATE FUNCTION user_session_audit_identity() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='INSERT' THEN NEW.audit_resource_id:=gen_random_uuid();
 ELSIF NEW.audit_resource_id IS DISTINCT FROM OLD.audit_resource_id THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Session audit identity is immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER user_session_audit_identity BEFORE INSERT OR UPDATE ON auth_user_sessions FOR EACH ROW EXECUTE FUNCTION user_session_audit_identity();

CREATE FUNCTION user_session_revoke_event_valid(h jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE k text; success boolean; home text;
BEGIN
 IF jsonb_typeof(h) IS DISTINCT FROM 'object' OR NOT h ?& ARRAY['schema_version','event_id','request_id','execution_id','attempt_id','record_kind','operation','selection_mode','actor_kind','actor_id','initiator_kind','initiator_user_id','home_organization_id','authority_source','authority_role','organization_role','affected_count','outcome','reason_code','occurred_at','recorded_at'] OR (SELECT count(*) FROM jsonb_object_keys(h))<>21 THEN RETURN false;END IF;
 IF (h->'schema_version'='1' AND h->>'operation'='user_session.revoke' AND h->>'selection_mode' IN ('selected_sessions','other_sessions_of_current_user')) IS NOT TRUE THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['event_id','request_id','execution_id','attempt_id'] LOOP
  IF (jsonb_typeof(h->k)='string' AND (h->>k)::uuid::text=h->>k AND (h->>k)::uuid<>'00000000-0000-0000-0000-000000000000') IS NOT TRUE THEN RETURN false;END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['actor_id','initiator_user_id','home_organization_id'] LOOP
  IF h->k<>'null' AND (jsonb_typeof(h->k)='string' AND (h->>k)::uuid::text=h->>k AND (h->>k)::uuid<>'00000000-0000-0000-0000-000000000000') IS NOT TRUE THEN RETURN false;END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['occurred_at','recorded_at'] LOOP
  IF (jsonb_typeof(h->k)='string' AND isfinite((h->>k)::timestamptz) AND extract(year FROM (h->>k)::timestamptz) BETWEEN 1 AND 9999) IS NOT TRUE THEN RETURN false;END IF;
 END LOOP;
 IF (jsonb_typeof(h->'affected_count')='string' AND (h->>'affected_count')::bigint>=0 AND (h->>'affected_count')::bigint::text=h->>'affected_count') IS NOT TRUE THEN RETURN false;END IF;
 success:=h->>'record_kind'='success_witness';home:=h->>'home_organization_id';
 IF (h->'initiator_kind'=h->'actor_kind' AND h->'initiator_user_id'=h->'actor_id') IS NOT TRUE THEN RETURN false;END IF;
 CASE h->>'actor_kind'
 WHEN 'human' THEN
  IF (h->'actor_id'<>'null' AND h->'home_organization_id'<>'null' AND h->>'authority_source'='current_local_user_organization_at_admission') IS NOT TRUE THEN RETURN false;END IF;
  IF home='296e2656-7221-53fe-bd0a-832d24ccfd03' THEN
   IF (h->>'organization_role'='NONE' AND h->>'authority_role' IN ('platform_admin','none')) IS NOT TRUE THEN RETURN false;END IF;
  ELSE
   IF (h->>'organization_role' IN ('ORG_ADMIN','ORG_MEMBER') AND (h->>'authority_role'='platform_admin' OR h->>'authority_role'='org_admin' AND h->>'organization_role'='ORG_ADMIN' OR h->>'authority_role'='org_member' AND h->>'organization_role'='ORG_MEMBER')) IS NOT TRUE THEN RETURN false;END IF;
  END IF;
 WHEN 'internal_system' THEN
  IF (h->'actor_id'='null' AND h->'home_organization_id'='null' AND h->>'authority_source'='trusted_internal_system' AND h->>'authority_role'='internal_system' AND h->>'organization_role'='unknown' AND h->>'selection_mode'='selected_sessions') IS NOT TRUE THEN RETURN false;END IF;
 WHEN 'unknown' THEN
  IF (NOT success AND h->'actor_id'='null' AND h->'home_organization_id'='null' AND h->>'authority_source'='unknown' AND h->>'authority_role'='unknown' AND h->>'organization_role'='unknown') IS NOT TRUE THEN RETURN false;END IF;
 ELSE RETURN false;
 END CASE;
 IF success THEN
  RETURN (h->>'outcome'='committed' AND h->>'reason_code'='revoked' AND (h->>'affected_count')::bigint>0) IS TRUE;
 END IF;
 RETURN (h->>'record_kind'='attempt_observation' AND h->>'affected_count'='0' AND (
 (h->>'outcome'='denied' AND h->>'reason_code' IN ('authority_denied','context_missing')) OR
 (h->>'outcome'='validation_failed' AND h->>'reason_code'='invalid_input') OR
 (h->>'outcome'='tx_failed' AND h->>'reason_code' IN ('begin_failed','mutation_failed','attribution_failed','receipt_invalid','audit_write_failed','commit_rejected','capacity_exhausted','transaction_ownership_unavailable')) OR
 (h->>'outcome'='commit_unknown' AND h->>'reason_code'='commit_unconfirmed') OR
 (h->>'outcome'='rollback_unconfirmed' AND h->>'reason_code'='rollback_unconfirmed'))) IS TRUE;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
CREATE TABLE user_session_revoke_audit_events (
 schema_version smallint NOT NULL DEFAULT 1,
 event_id uuid PRIMARY KEY,request_id uuid NOT NULL,execution_id uuid NOT NULL,attempt_id uuid NOT NULL,
 record_kind text NOT NULL,operation text NOT NULL,selection_mode text NOT NULL,
 actor_kind text NOT NULL,actor_id uuid,initiator_kind text NOT NULL,initiator_user_id uuid,home_organization_id uuid,
 authority_source text NOT NULL,authority_role text NOT NULL,organization_role text NOT NULL,
 affected_count bigint NOT NULL,outcome text NOT NULL,reason_code text NOT NULL,
 occurred_at timestamptz NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX user_session_revoke_success_execution ON user_session_revoke_audit_events(execution_id) WHERE record_kind='success_witness';
CREATE UNIQUE INDEX user_session_revoke_observation_attempt ON user_session_revoke_audit_events(attempt_id) WHERE record_kind='attempt_observation';
CREATE TABLE user_session_revoke_audit_details (
 event_id uuid NOT NULL REFERENCES user_session_revoke_audit_events(event_id),effect_ordinal bigint NOT NULL CHECK(effect_ordinal>=0),
 session_audit_id uuid NOT NULL UNIQUE CHECK(session_audit_id<>'00000000-0000-0000-0000-000000000000'),
 target_user_id uuid,target_organization_id uuid,target_org_resolution text NOT NULL,
 provenance text NOT NULL CHECK(provenance='EXPLICIT'),deletion_mechanism text NOT NULL CHECK(deletion_mechanism='explicit_sql'),cause text NOT NULL,
 PRIMARY KEY(event_id,effect_ordinal),
 CHECK(public.user_delete_org_valid(target_organization_id,target_org_resolution) IS TRUE),
 CHECK(target_user_id IS NOT NULL OR (target_organization_id IS NULL AND target_org_resolution='unknown'))
);
CREATE FUNCTION user_session_revoke_header_check() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE h jsonb;
BEGIN
 NEW.recorded_at:=clock_timestamp();
 h:=to_jsonb(NEW)||jsonb_build_object('affected_count',NEW.affected_count::text);
 IF public.user_session_revoke_event_valid(h) IS NOT TRUE THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Invalid Session revocation header';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER user_session_revoke_header_check BEFORE INSERT ON user_session_revoke_audit_events FOR EACH ROW EXECUTE FUNCTION user_session_revoke_header_check();
CREATE FUNCTION user_session_revoke_detail_check() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE h public.user_session_revoke_audit_events;
BEGIN
 SELECT * INTO STRICT h FROM public.user_session_revoke_audit_events WHERE event_id=NEW.event_id;
 IF h.record_kind<>'success_witness' OR NEW.effect_ordinal>=h.affected_count OR
 (h.selection_mode='selected_sessions' AND NEW.cause<>'explicit_target') OR
 (h.selection_mode='other_sessions_of_current_user' AND (NEW.cause<>'end_other_self_sessions' OR NEW.target_user_id IS DISTINCT FROM h.actor_id)) OR
 (h.actor_kind='human' AND h.home_organization_id='296e2656-7221-53fe-bd0a-832d24ccfd03' AND NEW.target_org_resolution<>'known_normal') THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Invalid Session revocation detail binding';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER user_session_revoke_detail_check BEFORE INSERT ON user_session_revoke_audit_details FOR EACH ROW EXECUTE FUNCTION user_session_revoke_detail_check();
CREATE FUNCTION user_session_revoke_complete() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE n bigint; lo bigint; hi bigint;
BEGIN
 SELECT count(*),min(effect_ordinal),max(effect_ordinal) INTO n,lo,hi FROM public.user_session_revoke_audit_details WHERE event_id=NEW.event_id;
 IF n<>NEW.affected_count OR (NEW.record_kind='success_witness' AND (lo<>0 OR hi<>n-1)) THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Incomplete Session revocation receipt';
 END IF;
 RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER user_session_revoke_complete AFTER INSERT ON user_session_revoke_audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION user_session_revoke_complete();
CREATE FUNCTION user_session_revoke_append_only() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Session revocation audit is append only';END;
$$;
CREATE TRIGGER user_session_revoke_events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON user_session_revoke_audit_events FOR EACH STATEMENT EXECUTE FUNCTION user_session_revoke_append_only();
CREATE TRIGGER user_session_revoke_details_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON user_session_revoke_audit_details FOR EACH STATEMENT EXECUTE FUNCTION user_session_revoke_append_only();
REVOKE ALL ON FUNCTION user_session_audit_identity(),user_session_revoke_event_valid(jsonb),user_session_revoke_header_check(),user_session_revoke_detail_check(),user_session_revoke_complete(),user_session_revoke_append_only() FROM PUBLIC;
