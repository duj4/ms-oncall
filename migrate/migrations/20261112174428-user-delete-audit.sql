-- +migrate Up
-- D09-SD8-USER-IMPL1: immutable User headers and complete paged B2 details.
-- No live business FK, production backfill, or change to business deletion rules.
CREATE FUNCTION user_delete_org_valid(id uuid, resolution text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT ((resolution='unknown' AND id IS NULL) OR (resolution='known_normal' AND id IS NOT NULL AND id NOT IN ('00000000-0000-0000-0000-000000000000','296e2656-7221-53fe-bd0a-832d24ccfd03')) OR (resolution='known_default' AND id='296e2656-7221-53fe-bd0a-832d24ccfd03')) IS TRUE
$$;
CREATE FUNCTION user_delete_scalar_valid(v jsonb, kind text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE s text;n bigint;dummy timestamptz;t time;
BEGIN
 IF v IS NULL THEN RETURN false; END IF;
 IF v='null' THEN RETURN kind IN ('U','I','T'); END IF;
 s:=v#>>'{}';
 CASE kind
 WHEN 'u','U' THEN RETURN jsonb_typeof(v)='string' AND s::uuid::text=s AND s::uuid<>'00000000-0000-0000-0000-000000000000';
 WHEN 'i','I','x','j','o','w' THEN
  IF jsonb_typeof(v)<>'number' OR s!~'^-?(0|[1-9][0-9]*)$' THEN RETURN false; END IF;
  n:=s::bigint;
  CASE kind WHEN 'x' THEN RETURN n BETWEEN 1 AND 4294967295;WHEN 'j' THEN RETURN n BETWEEN -2147483648 AND 2147483647;WHEN 'o' THEN RETURN n>=0;WHEN 'w' THEN RETURN n BETWEEN 0 AND 127;ELSE RETURN true;END CASE;
 WHEN 'b' THEN RETURN jsonb_typeof(v)='boolean';
 WHEN 'c' THEN
  IF jsonb_typeof(v)<>'string' OR s!~'^(([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,6})?|24:00:00(\.0{1,6})?)$' THEN RETURN false;END IF;
  t:=s::time;RETURN true;
 WHEN 't','T' THEN
  IF jsonb_typeof(v)<>'string' OR length(s)>48 THEN RETURN false; END IF;
  IF s IN ('infinity','-infinity') THEN RETURN true; END IF;
  IF s!~'^[0-9]{4,6}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(Z|\+00(:00)?)( BC)?$' THEN RETURN false;END IF;
  dummy:=s::timestamptz;RETURN true;
 ELSE RETURN jsonb_typeof(v)='string' AND s=ANY(string_to_array(kind,'|'));
 END CASE;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
CREATE FUNCTION user_delete_projection(typ text) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT $schema${"schedule_rule":{"key":"id","fields":{"id":"u","schedule_id":"u","target_user_id":"u","start":"c","end":"c","weekdays":"w","is_active":"b","row_version":"x"}},"rotation_participant":{"key":"id","fields":{"id":"u","rotation_id":"u","user_id":"u","position":"j","ordinal":"o","row_version":"x"}},"rotation_participant_count":{"key":"rotation_id","fields":{"rotation_id":"u","participant_count":"j"}},"rotation_state":{"key":"id","fields":{"id":"i","rotation_id":"u","participant_id":"u","position":"j","shift_start":"t","version":"j","row_version":"x"}},"user_override":{"key":"id","fields":{"id":"u","schedule_id":"u","add_user_id":"U","remove_user_id":"U","start":"t","end":"t","row_version":"x"}},"contact_method":{"key":"id","fields":{"id":"u","user_id":"u","type":"DEST|EMAIL|PUSH|SLACK_DM|SMS|VOICE|WEBHOOK","disabled":"b","pending":"b","private":"b","row_version":"x"}},"notification_rule":{"key":"id","fields":{"id":"u","user_id":"u","parent_cm_id":"u","delay_minutes":"j","row_version":"x"}},"user_favorite":{"key":"id","fields":{"id":"i","user_id":"u","target_user_id":"U","target_service_id":"U","target_schedule_id":"U","target_rotation_id":"U","target_escalation_policy_id":"U","row_version":"x"}},"escalation_policy_action":{"key":"id","fields":{"id":"u","step_id":"u","policy_id":"u","user_id":"u","row_version":"x"}},"schedule_on_call_history":{"key":"id","fields":{"id":"i","schedule_id":"u","user_id":"u","start":"t","end":"T","row_version":"x"}},"ep_step_on_call_history":{"key":"id","fields":{"id":"i","step_id":"u","policy_id":"u","user_id":"u","start":"t","end":"T","row_version":"x"}},"user_organization_assignment":{"key":"user_id","fields":{"user_id":"u","organization_id":"u","classification":"NORMAL|DEFAULT","organization_role":"ORG_ADMIN|ORG_MEMBER|NONE","row_version":"x"}},"auth_subject":{"key":"id","fields":{"id":"i","user_id":"u","cm_id":"U","row_version":"x"}},"user_session":{"key":"id","fields":{"id":"u","user_id":"u","row_version":"x"}},"basic_auth_link":{"key":"user_id","fields":{"user_id":"u","id":"i","row_version":"x"}},"user_status_contact_setting":{"key":"user_id","fields":{"user_id":"u","contact_method_id":"U","row_version":"x"}}}$schema$::jsonb->typ
$$;
CREATE FUNCTION user_delete_snapshot_valid(v jsonb, typ text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE schema jsonb;k text;kind text;
BEGIN
 schema:=public.user_delete_projection(typ)->'fields';
 IF schema IS NULL OR jsonb_typeof(v)<>'object' THEN RETURN false; END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(v))<>(SELECT count(*) FROM jsonb_object_keys(schema)) THEN RETURN false; END IF;
 FOR k,kind IN SELECT key,value FROM jsonb_each_text(schema) LOOP
  IF public.user_delete_scalar_valid(v->k,kind) IS NOT TRUE THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
CREATE FUNCTION user_delete_effect_valid(p jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE typ text;schema jsonb;identity text;change text;provenance text;mechanism text;k text;allowed text[];
BEGIN
 allowed:=ARRAY['effect_id','resource_type','resource_key','transition_slot','trigger_user_id','target_organization_id','org_resolution','change','provenance','deletion_mechanism','before','after'];
 IF jsonb_typeof(p)<>'object' OR NOT p ?& allowed OR (SELECT count(*) FROM jsonb_object_keys(p))<>array_length(allowed,1) OR octet_length(p::text)>4096 THEN RETURN false;END IF;
 IF public.user_delete_scalar_valid(p->'effect_id','u') IS NOT TRUE OR public.user_delete_scalar_valid(p->'trigger_user_id','u') IS NOT TRUE OR public.user_delete_scalar_valid(p->'target_organization_id','U') IS NOT TRUE OR public.user_delete_org_valid((p->>'target_organization_id')::uuid,p->>'org_resolution') IS NOT TRUE OR p->>'transition_slot'<>'row' THEN RETURN false;END IF;
 typ:=p->>'resource_type';schema:=public.user_delete_projection(typ);
 IF schema IS NULL OR public.user_delete_snapshot_valid(p->'before',typ) IS NOT TRUE THEN RETURN false;END IF;
 identity:=p->'before'->>(schema->>'key');
 IF jsonb_typeof(p->'resource_key')<>'string' OR p->>'resource_key' IS DISTINCT FROM identity THEN RETURN false;END IF;
 change:='deleted';provenance:='IMPLICIT_FK_CASCADE';mechanism:='fk_cascade';
 IF typ IN ('user_favorite','user_organization_assignment') THEN change:='relationship_removed';END IF;
 IF typ='rotation_participant' THEN
  IF p->'after'='null' THEN change:='relationship_removed';provenance:='IMPLICIT_APPLICATION_DELETE';mechanism:='explicit_sql';
  ELSE
   change:='relationship_reassigned';provenance:='IMPLICIT_APPLICATION_UPDATE';mechanism:='application_update';
   IF public.user_delete_snapshot_valid(p->'after',typ) IS NOT TRUE OR p->'before'->'user_id' IS NOT DISTINCT FROM p->'after'->'user_id' THEN RETURN false;END IF;
   FOREACH k IN ARRAY ARRAY['id','rotation_id','position','ordinal'] LOOP IF p->'before'->k IS DISTINCT FROM p->'after'->k THEN RETURN false;END IF;END LOOP;
  END IF;
 ELSIF typ IN ('rotation_participant_count','rotation_state') THEN
  IF p->'after'='null' THEN
   IF typ<>'rotation_state' THEN RETURN false;END IF;
   change:='deleted';provenance:='IMPLICIT_TRIGGER_DELETE';mechanism:='trigger_delete';
  ELSE
   change:='state_updated';provenance:='IMPLICIT_TRIGGER_UPDATE';mechanism:='trigger_update';
   IF public.user_delete_snapshot_valid(p->'after',typ) IS NOT TRUE OR p->'before' IS NOT DISTINCT FROM p->'after' OR p->'before'->(schema->>'key') IS DISTINCT FROM p->'after'->(schema->>'key') THEN RETURN false;END IF;
  END IF;
 ELSIF typ='user_status_contact_setting' THEN
  change:='relationship_cleared';provenance:='IMPLICIT_FK_SET_NULL';mechanism:='fk_set_null';
  IF public.user_delete_snapshot_valid(p->'after',typ) IS NOT TRUE OR p->'before'->'contact_method_id'='null' OR p->'after'->'contact_method_id'<>'null' OR p->'before'->'user_id' IS DISTINCT FROM p->'after'->'user_id' THEN RETURN false;END IF;
 ELSE IF p->'after'<>'null' THEN RETURN false;END IF;
 END IF;
 RETURN (p->>'change'=change AND p->>'provenance'=provenance AND p->>'deletion_mechanism'=mechanism) IS TRUE;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
CREATE FUNCTION user_delete_header_valid(h jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE b jsonb;ref jsonb;manifest_count bigint:=0;n bigint;k text;ids text[]:='{}';resources text[]:='{}';success boolean;
BEGIN
 -- Establish required types before nullable ->> comparisons can yield UNKNOWN.
 IF jsonb_typeof(h) IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['operation','root_type','record_kind','actor_kind','authority_source','authority_role','organization_role','target_org_resolution','provenance','deletion_mechanism','cause','outcome','reason_code','occurred_at'] LOOP
  IF jsonb_typeof(h->k) IS DISTINCT FROM 'string' THEN RETURN false;END IF;
 END LOOP;
 IF public.user_delete_scalar_valid(h->'schema_version','i') IS NOT TRUE OR public.user_delete_scalar_valid(h->'root_ordinal','I') IS NOT TRUE OR public.user_delete_scalar_valid(h->'effect_count','o') IS NOT TRUE OR public.user_delete_scalar_valid(h->'effect_json_bytes','o') IS NOT TRUE THEN RETURN false;END IF;
 IF octet_length(h::text)>32768 OR h->>'schema_version'<>'1' OR h->>'operation'<>'user.delete' OR h->>'root_type'<>'user' THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['event_id','request_id','execution_id','attempt_id'] LOOP IF public.user_delete_scalar_valid(h->k,'u') IS NOT TRUE THEN RETURN false;END IF;END LOOP;
 FOREACH k IN ARRAY ARRAY['root_id','actor_id','home_organization_id','target_organization_id'] LOOP IF public.user_delete_scalar_valid(h->k,'U') IS NOT TRUE THEN RETURN false;END IF;END LOOP;
 IF public.user_delete_org_valid((h->>'target_organization_id')::uuid,h->>'target_org_resolution') IS NOT TRUE OR NOT isfinite((h->>'occurred_at')::timestamptz) THEN RETURN false;END IF;
 IF h->'root_id'='null' AND (h->'root_ordinal'<>'null' OR h->>'target_org_resolution'<>'unknown') THEN RETURN false;END IF;
 IF h->'root_ordinal'<>'null' AND (h->>'root_ordinal')::integer NOT BETWEEN 0 AND 99 THEN RETURN false;END IF;
 success:=h->>'record_kind'='success_witness';
 CASE h->>'actor_kind'
 WHEN 'human' THEN
  IF h->'actor_id'='null' OR h->'home_organization_id'='null' OR h->>'authority_source'<>'current_local_user_organization_at_admission' THEN RETURN false;END IF;
  IF h->>'home_organization_id'='296e2656-7221-53fe-bd0a-832d24ccfd03' THEN
   IF h->>'organization_role'<>'NONE' OR h->>'authority_role' NOT IN ('platform_admin','none') THEN RETURN false;END IF;
   IF success AND h->>'target_org_resolution'<>'known_normal' THEN RETURN false;END IF;
  ELSE
   IF h->>'organization_role' NOT IN ('ORG_ADMIN','ORG_MEMBER') OR NOT (h->>'authority_role'='platform_admin' OR h->>'authority_role'='org_admin' AND h->>'organization_role'='ORG_ADMIN' OR h->>'authority_role'='org_member' AND h->>'organization_role'='ORG_MEMBER') THEN RETURN false;END IF;
  END IF;
  IF success AND h->>'authority_role'<>'platform_admin' THEN RETURN false;END IF;
 WHEN 'internal_system' THEN IF h->'actor_id'<>'null' OR h->'home_organization_id'<>'null' OR h->>'authority_source'<>'trusted_internal_system' OR h->>'authority_role'<>'internal_system' OR h->>'organization_role'<>'unknown' THEN RETURN false;END IF;
 WHEN 'unknown' THEN IF success OR h->'actor_id'<>'null' OR h->'home_organization_id'<>'null' OR h->>'authority_source'<>'unknown' OR h->>'authority_role'<>'unknown' OR h->>'organization_role'<>'unknown' THEN RETURN false;END IF;
 ELSE RETURN false;
 END CASE;
 IF success THEN
  b:=h->'before_context';
  IF h->>'outcome'<>'committed' OR h->>'reason_code'<>'deleted' OR h->'root_id'='null' OR h->'root_ordinal'='null' OR h->>'provenance'<>'EXPLICIT' OR h->>'deletion_mechanism'<>'explicit_sql' OR h->>'cause'<>'explicit_target' OR jsonb_typeof(b) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(b))<>9 OR NOT b ?& ARRAY['version','user_id','user_role','row_version','assignment_present','assignment_row_version','target_organization_id','target_org_resolution','organization_role'] THEN RETURN false;END IF;
  IF b->'version'<>'1' OR b->'user_id' IS DISTINCT FROM h->'root_id' OR public.user_delete_scalar_valid(b->'user_role','user|admin|unknown') IS NOT TRUE OR public.user_delete_scalar_valid(b->'row_version','x') IS NOT TRUE OR jsonb_typeof(b->'assignment_present') IS DISTINCT FROM 'boolean' OR b->'target_organization_id' IS DISTINCT FROM h->'target_organization_id' OR b->'target_org_resolution' IS DISTINCT FROM h->'target_org_resolution' OR public.user_delete_scalar_valid(b->'organization_role','unknown|NONE|ORG_ADMIN|ORG_MEMBER') IS NOT TRUE THEN RETURN false;END IF;
  IF b->'assignment_present'='true' THEN IF public.user_delete_scalar_valid(b->'assignment_row_version','x') IS NOT TRUE THEN RETURN false;END IF;
  ELSE IF b->'assignment_row_version'<>'null' OR b->>'organization_role'<>'unknown' OR b->>'target_org_resolution'<>'unknown' THEN RETURN false;END IF;END IF;
 ELSE
  IF h->>'record_kind'<>'attempt_observation' OR h->'before_context' IS DISTINCT FROM 'null'::jsonb OR h->>'provenance'<>'' OR h->>'deletion_mechanism'<>'' OR h->>'cause'<>'' OR h->'effect_count'<>'0' OR h->'effect_json_bytes'<>'0' OR h->'manifest'<>'{}' OR h->'related_explicit_events'<>'[]' THEN RETURN false;END IF;
  IF NOT ((h->>'outcome'='denied' AND h->>'reason_code'='authority_denied') OR (h->>'outcome'='validation_failed' AND h->>'reason_code' IN ('invalid_fields','target_unavailable')) OR (h->>'outcome'='tx_failed' AND h->>'reason_code' IN ('begin_failed','write_failed','audit_write_failed','commit_rejected')) OR (h->>'outcome'='commit_unknown' AND h->>'reason_code'='commit_unconfirmed') OR (h->>'outcome'='rollback_unconfirmed' AND h->>'reason_code'='rollback_unconfirmed')) THEN RETURN false;END IF;
 END IF;
 IF jsonb_typeof(h->'manifest') IS DISTINCT FROM 'object' OR (h->>'effect_count')::bigint<0 OR (h->>'effect_json_bytes')::bigint<0 THEN RETURN false;END IF;
 FOR k,n IN SELECT key,value::bigint FROM jsonb_each_text(h->'manifest') LOOP
  IF public.user_delete_projection(k) IS NULL OR public.user_delete_scalar_valid(h->'manifest'->k,'o') IS NOT TRUE OR n<=0 THEN RETURN false;END IF;manifest_count:=manifest_count+n;
 END LOOP;
 IF manifest_count<>(h->>'effect_count')::bigint OR jsonb_typeof(h->'related_explicit_events') IS DISTINCT FROM 'array' OR jsonb_array_length(h->'related_explicit_events')>100 THEN RETURN false;END IF;
 FOR ref IN SELECT value FROM jsonb_array_elements(h->'related_explicit_events') LOOP
  IF jsonb_typeof(ref) IS DISTINCT FROM 'object' OR NOT ref ?& ARRAY['event_id','resource_type','resource_id'] OR (SELECT count(*) FROM jsonb_object_keys(ref))<>3 OR public.user_delete_scalar_valid(ref->'resource_type','contact_method|notification_rule') IS NOT TRUE OR public.user_delete_scalar_valid(ref->'event_id','u') IS NOT TRUE OR public.user_delete_scalar_valid(ref->'resource_id','u') IS NOT TRUE OR ref->'event_id'=h->'event_id' OR ref->>'event_id'=ANY(ids) OR ((ref->>'resource_type')||(ref->>'resource_id'))=ANY(resources) THEN RETURN false;END IF;
  ids:=array_append(ids,ref->>'event_id');resources:=array_append(resources,(ref->>'resource_type')||(ref->>'resource_id'));
 END LOOP;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
CREATE TABLE user_delete_audit_events (
 schema_version smallint NOT NULL DEFAULT 1 CHECK(schema_version=1),
 event_id uuid PRIMARY KEY,request_id uuid NOT NULL,execution_id uuid NOT NULL,attempt_id uuid NOT NULL,
 record_kind text NOT NULL,operation text NOT NULL DEFAULT 'user.delete',root_type text NOT NULL DEFAULT 'user',root_id uuid,root_ordinal integer,
 actor_kind text NOT NULL,actor_id uuid,home_organization_id uuid,authority_source text NOT NULL,authority_role text NOT NULL,organization_role text NOT NULL,
 target_organization_id uuid,target_org_resolution text NOT NULL,before_context jsonb NOT NULL DEFAULT 'null',
 provenance text NOT NULL DEFAULT '',deletion_mechanism text NOT NULL DEFAULT '',cause text NOT NULL DEFAULT '',
 effect_count bigint NOT NULL DEFAULT 0,effect_json_bytes bigint NOT NULL DEFAULT 0,manifest jsonb NOT NULL DEFAULT '{}',related_explicit_events jsonb NOT NULL DEFAULT '[]',
 outcome text NOT NULL,reason_code text NOT NULL,occurred_at timestamptz NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(recorded_at)),
 UNIQUE(event_id,effect_count),
 CONSTRAINT user_delete_header_closed CHECK(public.user_delete_header_valid(jsonb_build_object('schema_version',schema_version,'event_id',event_id,'request_id',request_id,'execution_id',execution_id,'attempt_id',attempt_id,'record_kind',record_kind,'operation',operation,'root_type',root_type,'root_id',root_id,'root_ordinal',root_ordinal,'actor_kind',actor_kind,'actor_id',actor_id,'home_organization_id',home_organization_id,'authority_source',authority_source,'authority_role',authority_role,'organization_role',organization_role,'target_organization_id',target_organization_id,'target_org_resolution',target_org_resolution,'before_context',before_context,'provenance',provenance,'deletion_mechanism',deletion_mechanism,'cause',cause,'effect_count',effect_count,'effect_json_bytes',effect_json_bytes,'manifest',manifest,'related_explicit_events',related_explicit_events,'outcome',outcome,'reason_code',reason_code,'occurred_at',occurred_at)) IS TRUE),CHECK(octet_length((jsonb_build_object('schema_version',schema_version,'event_id',event_id,'request_id',request_id,'execution_id',execution_id,'attempt_id',attempt_id,'record_kind',record_kind,'operation',operation,'root_type',root_type,'root_id',root_id,'root_ordinal',root_ordinal,'actor_kind',actor_kind,'actor_id',actor_id,'home_organization_id',home_organization_id,'authority_source',authority_source,'authority_role',authority_role,'organization_role',organization_role,'target_organization_id',target_organization_id,'target_org_resolution',target_org_resolution,'before_context',before_context,'provenance',provenance,'deletion_mechanism',deletion_mechanism,'cause',cause,'effect_count',effect_count,'effect_json_bytes',effect_json_bytes,'manifest',manifest,'related_explicit_events',related_explicit_events,'outcome',outcome,'reason_code',reason_code,'occurred_at',occurred_at)||jsonb_build_object('recorded_at',recorded_at))::text)<=32768)
);
CREATE TABLE user_delete_audit_effects (
 event_id uuid NOT NULL,effect_ordinal bigint NOT NULL,declared_effect_count bigint NOT NULL,
 effect_id uuid NOT NULL UNIQUE,resource_type text NOT NULL,resource_key text NOT NULL,transition_slot text NOT NULL,payload jsonb NOT NULL,
 PRIMARY KEY(event_id,effect_ordinal),UNIQUE(event_id,resource_type,resource_key,transition_slot),
 CHECK(effect_ordinal>=0 AND effect_ordinal<declared_effect_count),
 FOREIGN KEY(event_id,declared_effect_count) REFERENCES user_delete_audit_events(event_id,effect_count) ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CONSTRAINT user_delete_effect_closed CHECK((public.user_delete_effect_valid(payload) IS TRUE AND payload->>'effect_id'=effect_id::text AND payload->>'resource_type'=resource_type AND payload->>'resource_key'=resource_key AND payload->>'transition_slot'=transition_slot) IS TRUE)
);
CREATE UNIQUE INDEX user_delete_success_ordinal ON user_delete_audit_events(attempt_id,root_ordinal) WHERE record_kind='success_witness';
CREATE UNIQUE INDEX user_delete_success_target ON user_delete_audit_events(attempt_id,root_id) WHERE record_kind='success_witness';
CREATE INDEX user_delete_correlation ON user_delete_audit_events(request_id,execution_id,attempt_id);
CREATE INDEX user_delete_root ON user_delete_audit_events(root_id,occurred_at,event_id);
CREATE INDEX user_delete_actor ON user_delete_audit_events(actor_id,occurred_at,event_id);
CREATE INDEX user_delete_target_org ON user_delete_audit_events(target_organization_id,occurred_at,event_id);
CREATE FUNCTION user_delete_manifest_complete() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE n bigint;first_slot bigint;last_slot bigint;bytes bigint;actual jsonb;ref jsonb;
BEGIN
 SELECT count(*),min(effect_ordinal),max(effect_ordinal),coalesce(sum(octet_length(payload::text)),0) INTO n,first_slot,last_slot,bytes FROM public.user_delete_audit_effects WHERE event_id=NEW.event_id;
 IF n<>NEW.effect_count OR bytes<>NEW.effect_json_bytes OR (n>0 AND (first_slot<>0 OR last_slot<>n-1)) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='user.delete manifest incomplete';END IF;
 SELECT coalesce(jsonb_object_agg(resource_type,count),'{}') INTO actual FROM (SELECT resource_type,count(*) FROM public.user_delete_audit_effects WHERE event_id=NEW.event_id GROUP BY resource_type) counts;
 IF actual<>NEW.manifest OR EXISTS(SELECT FROM public.user_delete_audit_effects WHERE event_id=NEW.event_id AND payload->>'trigger_user_id' IS DISTINCT FROM NEW.root_id::text) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='user.delete manifest mismatch';END IF;
 IF EXISTS(SELECT FROM public.user_delete_audit_effects f WHERE f.event_id=NEW.event_id AND (
  (f.resource_type='schedule_rule' AND f.payload->'before'->>'target_user_id' IS DISTINCT FROM NEW.root_id::text)
  OR (f.resource_type='user_override' AND f.payload->'before'->>'add_user_id' IS DISTINCT FROM NEW.root_id::text AND f.payload->'before'->>'remove_user_id' IS DISTINCT FROM NEW.root_id::text)
  OR (f.resource_type IN ('contact_method','escalation_policy_action','schedule_on_call_history','ep_step_on_call_history','user_organization_assignment','user_session','basic_auth_link') AND f.payload->'before'->>'user_id' IS DISTINCT FROM NEW.root_id::text)
  OR (f.resource_type='user_favorite' AND f.payload->'before'->>'user_id' IS DISTINCT FROM NEW.root_id::text AND f.payload->'before'->>'target_user_id' IS DISTINCT FROM NEW.root_id::text)
  OR (f.resource_type='notification_rule' AND f.payload->'before'->>'user_id' IS DISTINCT FROM NEW.root_id::text AND public.user_delete_cm_caused(NEW.event_id,(f.payload->'before'->>'parent_cm_id')::uuid) IS NOT TRUE)
  OR (f.resource_type='auth_subject' AND f.payload->'before'->>'user_id' IS DISTINCT FROM NEW.root_id::text AND public.user_delete_cm_caused(NEW.event_id,(f.payload->'before'->>'cm_id')::uuid) IS NOT TRUE)
  OR (f.resource_type='user_status_contact_setting' AND (f.payload->'before'->>'user_id'=NEW.root_id::text OR public.user_delete_cm_caused(NEW.event_id,(f.payload->'before'->>'contact_method_id')::uuid) IS NOT TRUE)))) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='user.delete effect cause mismatch';END IF;
 FOR ref IN SELECT value FROM jsonb_array_elements(NEW.related_explicit_events) LOOP
  IF NOT EXISTS(SELECT FROM public.user_cmnr_delete_audit_events c WHERE c.event_id=(ref->>'event_id')::uuid AND c.root_type=ref->>'resource_type' AND c.root_id=(ref->>'resource_id')::uuid AND c.schema_version=2 AND c.cause_event_id=NEW.event_id) OR EXISTS(SELECT FROM public.user_delete_audit_effects f WHERE f.event_id=NEW.event_id AND f.resource_type=ref->>'resource_type' AND f.resource_key=ref->>'resource_id') THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='user.delete explicit cause mismatch';END IF;
 END LOOP;
 RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER user_delete_complete AFTER INSERT ON user_delete_audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION user_delete_manifest_complete();
CREATE FUNCTION user_delete_append_only() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='user.delete audit is append-only';END;
$$;
CREATE TRIGGER user_delete_header_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON user_delete_audit_events FOR EACH STATEMENT EXECUTE FUNCTION user_delete_append_only();
CREATE TRIGGER user_delete_detail_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON user_delete_audit_effects FOR EACH STATEMENT EXECUTE FUNCTION user_delete_append_only();
-- v1 has no witness. Both empty representations preserve legacy JSON record-copy
-- semantics. v2 always requires a closed, non-NULL object below.
ALTER TABLE user_cmnr_delete_audit_events ADD COLUMN cause_root_type text,ADD COLUMN cause_root_id uuid,ADD COLUMN user_cause_witness jsonb DEFAULT 'null';
ALTER TABLE user_cmnr_delete_audit_events DROP CONSTRAINT user_cmnr_delete_audit_events_schema_version_check,ADD CONSTRAINT user_cmnr_delete_version CHECK(schema_version IN (1,2));
-- Preserve the exact existing v1 expressions obtained from the frozen schema.
DO $$
DECLARE old_expression text;
BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO STRICT old_expression FROM pg_constraint WHERE conrelid='public.user_cmnr_delete_audit_events'::regclass AND conname='user_cmnr_delete_audit_events_check3';
 ALTER TABLE public.user_cmnr_delete_audit_events DROP CONSTRAINT user_cmnr_delete_audit_events_check3;
 EXECUTE 'ALTER TABLE public.user_cmnr_delete_audit_events ADD CONSTRAINT user_cmnr_delete_outcome_versioned CHECK(((schema_version=1 AND ('||old_expression||')) OR (schema_version=2 AND record_kind=''success_witness'' AND outcome=''committed'' AND reason_code=''deleted'' AND provenance=''EXPLICIT'' AND deletion_mechanism=''fk_cascade'' AND root_id IS NOT NULL AND cause_event_id IS NOT NULL AND cause_event_id<>event_id AND effects=''[]''::jsonb)) IS TRUE)';
 SELECT pg_get_expr(conbin,conrelid) INTO STRICT old_expression FROM pg_constraint WHERE conrelid='public.user_cmnr_delete_audit_events'::regclass AND conname='user_cmnr_delete_audit_events_check5';
 ALTER TABLE public.user_cmnr_delete_audit_events DROP CONSTRAINT user_cmnr_delete_audit_events_check5;
 EXECUTE 'ALTER TABLE public.user_cmnr_delete_audit_events ADD CONSTRAINT user_cmnr_delete_authority_versioned CHECK(((schema_version=1 AND ('||old_expression||')) OR (schema_version=2 AND (actor_kind=''internal_system'' OR actor_kind=''human'' AND authority_role=''platform_admin''))) IS TRUE)';
END;
$$;
CREATE FUNCTION user_delete_cm_caused(own_event uuid,cm uuid) RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog AS $$
 SELECT cm IS NOT NULL AND (EXISTS(SELECT FROM public.user_delete_audit_effects f JOIN public.user_delete_audit_events u USING(event_id) WHERE f.event_id=own_event AND f.resource_type='contact_method' AND f.resource_key=cm::text AND f.payload->'before'->>'user_id'=u.root_id::text)
 OR EXISTS(SELECT FROM public.user_cmnr_delete_audit_events c WHERE c.schema_version=2 AND c.cause_event_id=own_event AND c.root_type='contact_method' AND c.root_id=cm AND c.root_owner_user_id=c.cause_root_id))
$$;
CREATE FUNCTION user_delete_cmnr_cause_complete() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE u public.user_delete_audit_events;w jsonb;k text;allowed text[];
BEGIN
 IF NEW.schema_version=1 THEN RETURN NULL;END IF;
 w:=NEW.user_cause_witness;
 allowed:=ARRAY['event_id','resource_type','resource_id','intent_ordinal','owner_id','parent_cm_id','target_organization_id','target_org_resolution','row_version','cause_user_id','cause_event_id','request_id','execution_id','attempt_id','owner_fk','contact_method_fk','verified'];
 IF NEW.cause_root_type IS DISTINCT FROM 'user' OR NEW.cause_root_id IS NULL OR jsonb_typeof(w)<>'object' OR NOT w ?& allowed OR (SELECT count(*) FROM jsonb_object_keys(w))<>array_length(allowed,1) OR w->'verified' IS DISTINCT FROM 'true'::jsonb OR public.user_delete_scalar_valid(w->'row_version','x') IS NOT TRUE OR public.user_delete_scalar_valid(w->'intent_ordinal','i') IS NOT TRUE OR (w->>'intent_ordinal')::integer NOT BETWEEN 0 AND 49 THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='invalid user cause witness';END IF;
 IF ROW(w->>'event_id',w->>'resource_type',w->>'resource_id',w->>'owner_id',w->>'parent_cm_id',w->>'target_organization_id',w->>'target_org_resolution',w->>'cause_user_id',w->>'cause_event_id',w->>'request_id',w->>'execution_id',w->>'attempt_id') IS DISTINCT FROM ROW(NEW.event_id::text,NEW.root_type,NEW.root_id::text,NEW.root_owner_user_id::text,NEW.parent_cm_id::text,NEW.target_organization_id::text,NEW.target_org_resolution,NEW.cause_root_id::text,NEW.cause_event_id::text,NEW.request_id::text,NEW.execution_id::text,NEW.attempt_id::text) OR jsonb_typeof(w->'owner_fk')<>'boolean' OR jsonb_typeof(w->'contact_method_fk')<>'boolean' OR (w->>'owner_fk')::boolean IS DISTINCT FROM (NEW.root_owner_user_id=NEW.cause_root_id) OR NOT ((w->>'owner_fk')::boolean OR (w->>'contact_method_fk')::boolean) OR (NEW.root_type='contact_method' AND ((w->>'contact_method_fk')::boolean OR NOT (w->>'owner_fk')::boolean)) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='user cause identity mismatch';END IF;
 IF (w->>'contact_method_fk')::boolean AND public.user_delete_cm_caused(NEW.cause_event_id,NEW.parent_cm_id) IS NOT TRUE THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='user cause parent mismatch';END IF;
 SELECT * INTO u FROM public.user_delete_audit_events WHERE event_id=NEW.cause_event_id;
 IF NOT FOUND OR u.record_kind<>'success_witness' OR u.root_id<>NEW.cause_root_id OR ROW(u.request_id,u.execution_id,u.attempt_id,u.actor_kind,u.actor_id,u.home_organization_id,u.authority_source,u.authority_role,u.organization_role) IS DISTINCT FROM ROW(NEW.request_id,NEW.execution_id,NEW.attempt_id,NEW.actor_kind,NEW.actor_id,NEW.home_organization_id,NEW.authority_source,NEW.authority_role,NEW.organization_role) OR NOT u.related_explicit_events @> jsonb_build_array(jsonb_build_object('event_id',NEW.event_id,'resource_type',NEW.root_type,'resource_id',NEW.root_id)) OR EXISTS(SELECT FROM public.user_delete_audit_effects f WHERE f.event_id=u.event_id AND f.resource_type=NEW.root_type AND f.resource_key=NEW.root_id::text) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='user cause root mismatch';END IF;
 IF NEW.root_owner_user_id=u.root_id AND ROW(NEW.target_organization_id,NEW.target_org_resolution) IS DISTINCT FROM ROW(u.target_organization_id,u.target_org_resolution) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='user cause organization mismatch';END IF;
 RETURN NULL;
END;
$$;
ALTER TABLE user_cmnr_delete_audit_events ADD CONSTRAINT user_cmnr_delete_user_cause_version CHECK(((schema_version=1 AND cause_root_type IS NULL AND cause_root_id IS NULL AND coalesce(user_cause_witness,'null'::jsonb)='null') OR (schema_version=2 AND cause_root_type='user' AND cause_root_id IS NOT NULL AND cause_root_id<>'00000000-0000-0000-0000-000000000000' AND jsonb_typeof(user_cause_witness)='object' AND effects='[]')) IS TRUE);
CREATE CONSTRAINT TRIGGER user_cmnr_delete_user_cause_complete AFTER INSERT ON user_cmnr_delete_audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION user_delete_cmnr_cause_complete();
REVOKE ALL ON user_delete_audit_events,user_delete_audit_effects FROM PUBLIC;
REVOKE ALL ON FUNCTION user_delete_org_valid(uuid,text),user_delete_scalar_valid(jsonb,text),user_delete_projection(text),user_delete_snapshot_valid(jsonb,text),user_delete_effect_valid(jsonb),user_delete_header_valid(jsonb),user_delete_manifest_complete(),user_delete_append_only(),user_delete_cmnr_cause_complete(),user_delete_cm_caused(uuid,uuid) FROM PUBLIC;
-- +migrate Down
DO $$BEGIN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='user.delete audit downgrade refused: preserve audit history';END;$$;
