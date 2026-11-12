-- +migrate Up

CREATE FUNCTION schedule_rotation_delete_time_valid(v jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
BEGIN
 RETURN (jsonb_typeof(v)='string' AND v#>>'{}' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T.*(Z|[+-][0-9]{2}:[0-9]{2})$'
 AND isfinite((v#>>'{}')::timestamptz) AND extract(year FROM (v#>>'{}')::timestamptz) BETWEEN 1 AND 9999) IS TRUE;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;

CREATE FUNCTION schedule_rotation_delete_effects_valid(effects jsonb,state jsonb,root uuid,org uuid,typ text,human boolean) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE f jsonb; d jsonb; identity jsonb; k text; v jsonb; kind text; payload text;
 expected text[]; fields text[]; uuid_fields text[]; numeric boolean; fragment boolean;
BEGIN
 IF typ NOT IN ('schedule','rotation') OR jsonb_typeof(effects)<>'array' OR state IS NULL THEN RETURN false; END IF;
 IF jsonb_array_length(effects)+(CASE WHEN state='null' THEN 0 ELSE 1 END)>16384
 OR octet_length(effects::text)+(CASE WHEN state='null' THEN 0 ELSE octet_length(state::text) END)>8388608 THEN RETURN false; END IF;
 IF (SELECT count(DISTINCT (value->>'effect_id')::uuid) FROM jsonb_array_elements(effects))<>jsonb_array_length(effects) THEN RETURN false; END IF;
 IF (SELECT count(DISTINCT ROW(value->>'resource_type',coalesce(value->>'resource_uuid',value->>'resource_numeric_id',(value->'event_time_identity')::text))) FROM jsonb_array_elements(effects))<>jsonb_array_length(effects) THEN RETURN false; END IF;
 FOR f IN SELECT value FROM jsonb_array_elements(effects) LOOP
  IF jsonb_typeof(f)<>'object' THEN RETURN false; END IF;
  kind=f->>'resource_type'; numeric=false; fragment=false;
  CASE kind
   WHEN 'schedule_rule' THEN payload='rule';fields=ARRAY['schedule_id','schedule_organization_id','target_kind','target_id','start','end','weekdays'];uuid_fields=ARRAY['schedule_id','schedule_organization_id','target_id'];
   WHEN 'user_override' THEN payload='override';fields=ARRAY['add_user_id','remove_user_id','start','end'];uuid_fields=ARRAY[]::text[];
   WHEN 'favorite' THEN
    payload='favorite';numeric=true;fields=ARRAY['owner_user_id','owner_org_resolution'];uuid_fields=ARRAY['owner_user_id'];
    IF f#>>'{favorite,owner_org_resolution}' IN ('known_normal','known_default') THEN fields=array_append(fields,'owner_organization_id');uuid_fields=array_append(uuid_fields,'owner_organization_id');END IF;
   WHEN 'rotation_participant' THEN payload='participant';fields=ARRAY['user_id','position'];uuid_fields=ARRAY['user_id'];
   WHEN 'escalation_policy_action' THEN payload='action';fields=ARRAY['policy_id','policy_organization_id','step_id'];uuid_fields=fields;
   WHEN 'temporary_schedule' THEN payload='temporary';fragment=true;fields=ARRAY['start','end'];uuid_fields=ARRAY[]::text[];
   WHEN 'fixed_shift' THEN payload='shift';fragment=true;fields=ARRAY['user_id','start','end'];uuid_fields=ARRAY['user_id'];
   WHEN 'on_call_notification_rule' THEN payload='on_call_rule';fragment=true;fields=ARRAY['local_id','channel_id','time','weekdays'];uuid_fields=ARRAY['channel_id'];
   WHEN 'schedule_on_call_history' THEN payload='history';numeric=true;fields=ARRAY['user_id','start','end'];uuid_fields=ARRAY['user_id'];
   ELSE RETURN false;
  END CASE;
  IF typ='rotation' AND kind NOT IN ('schedule_rule','favorite','rotation_participant','escalation_policy_action') OR typ='schedule' AND kind='rotation_participant' THEN RETURN false; END IF;
  expected=ARRAY['effect_id','resource_type','root_id','target_organization_id','relation','change','provenance','deletion_mechanism','cause',payload];
  expected=array_append(expected,CASE WHEN numeric THEN 'resource_numeric_id' WHEN fragment THEN 'event_time_identity' ELSE 'resource_uuid' END);
  IF NOT(f ?& expected) OR (SELECT count(*) FROM jsonb_object_keys(f))<>cardinality(expected) THEN RETURN false; END IF;
  FOR k,v IN SELECT * FROM jsonb_each(f) LOOP
   IF k=payload OR k='event_time_identity' THEN IF jsonb_typeof(v)<>'object' THEN RETURN false; END IF;
   ELSIF k='resource_numeric_id' THEN IF jsonb_typeof(v)<>'number' OR v::text!~'^[0-9]+$' OR (v::text)::bigint<=0 THEN RETURN false;END IF;
   ELSIF jsonb_typeof(v)<>'string' THEN RETURN false;
   END IF;
   IF k IN ('effect_id','root_id','target_organization_id','resource_uuid') AND (f->>k)::uuid='00000000-0000-0000-0000-000000000000' THEN RETURN false;END IF;
  END LOOP;
  IF ((f->>'root_id')::uuid=root AND (f->>'target_organization_id')::uuid=org AND f->>'relation'=CASE WHEN kind='rotation_participant' THEN 'rotation.participant' ELSE typ||'.'||kind END AND f->>'cause'=typ||'_delete' AND f->>'provenance'='CASCADE'
   AND f->>'deletion_mechanism'=CASE WHEN fragment THEN 'envelope_cascade' ELSE 'fk_cascade' END
   AND f->>'change'=CASE WHEN kind IN ('favorite','rotation_participant') THEN 'relationship_removed' ELSE 'deleted' END) IS NOT TRUE THEN RETURN false; END IF;
  d=f->payload;
  IF NOT(d ?& fields) OR (SELECT count(*) FROM jsonb_object_keys(d))<>cardinality(fields) THEN RETURN false; END IF;
  FOREACH k IN ARRAY uuid_fields LOOP
   IF (jsonb_typeof(d->k)='string' AND (d->>k)::uuid<>'00000000-0000-0000-0000-000000000000') IS NOT TRUE THEN RETURN false;END IF;
  END LOOP;
  IF fragment THEN
   identity=f->'event_time_identity';expected=ARRAY['envelope_id','ordinal'];IF kind='fixed_shift' THEN expected=array_append(expected,'parent_ordinal');END IF;
   IF NOT(identity ?& expected) OR (SELECT count(*) FROM jsonb_object_keys(identity))<>cardinality(expected) THEN RETURN false;END IF;
   FOR k,v IN SELECT * FROM jsonb_each(identity) LOOP
    IF jsonb_typeof(v)<>'number' OR v::text!~'^[0-9]+$' OR (k='envelope_id' AND v::text::bigint<=0) OR (k<>'envelope_id' AND v::text::integer<0) THEN RETURN false;END IF;
   END LOOP;
  END IF;
  CASE kind
   WHEN 'schedule_rule' THEN
    IF (jsonb_typeof(d->'target_kind')='string' AND d->>'target_kind' IN ('user','rotation') AND jsonb_typeof(d->'start')='string' AND jsonb_typeof(d->'end')='string'
     AND d->>'start' ~ '^([01][0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9](\.[0-9]{1,9})?)?$|^24:00:00$' AND d->>'end' ~ '^([01][0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9](\.[0-9]{1,9})?)?$|^24:00:00$'
     AND jsonb_typeof(d->'weekdays')='string' AND d->>'weekdays' ~ '^[01]{7}$'
     AND (typ='schedule' AND (d->>'schedule_id')::uuid=root OR typ='rotation' AND d->>'target_kind'='rotation' AND (d->>'target_id')::uuid=root)
     AND (NOT human OR (d->>'schedule_organization_id')::uuid=org)) IS NOT TRUE THEN RETURN false;END IF;
   WHEN 'user_override' THEN
    FOREACH k IN ARRAY ARRAY['add_user_id','remove_user_id'] LOOP
     IF d->k<>'null' AND (jsonb_typeof(d->k)<>'string' OR (d->>k)::uuid='00000000-0000-0000-0000-000000000000') THEN RETURN false;END IF;
    END LOOP;
    IF d->'add_user_id'='null' AND d->'remove_user_id'='null' OR d->'add_user_id'=d->'remove_user_id' THEN RETURN false;END IF;
   WHEN 'favorite' THEN
    IF (d->>'owner_org_resolution'='unknown' OR d->>'owner_org_resolution'='known_normal' AND (d->>'owner_organization_id')::uuid<>'296e2656-7221-53fe-bd0a-832d24ccfd03' OR d->>'owner_org_resolution'='known_default' AND (d->>'owner_organization_id')::uuid='296e2656-7221-53fe-bd0a-832d24ccfd03') IS NOT TRUE THEN RETURN false;END IF;
   WHEN 'rotation_participant' THEN
    IF (jsonb_typeof(d->'position')='number' AND d->>'position' ~ '^[0-9]+$' AND (d->>'position')::integer>=0) IS NOT TRUE THEN RETURN false;END IF;
   WHEN 'escalation_policy_action' THEN
    IF human AND (d->>'policy_organization_id')::uuid<>org THEN RETURN false;END IF;
   WHEN 'on_call_notification_rule' THEN
    IF (jsonb_typeof(d->'local_id')='number' AND d->>'local_id' ~ '^[0-9]+$' AND (d->>'local_id')::integer>=0
     AND (d->'time'='null' OR jsonb_typeof(d->'time')='string' AND d->>'time' ~ '^([01][0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9](\.[0-9]{1,9})?)?$|^24:00:00$')
     AND (d->'weekdays'='null' OR jsonb_typeof(d->'weekdays')='string' AND d->>'weekdays' ~ '^[01]{7}$')) IS NOT TRUE THEN RETURN false;END IF;
   ELSE NULL;
  END CASE;
  IF kind IN ('user_override','temporary_schedule','fixed_shift','schedule_on_call_history') THEN
   IF NOT public.schedule_rotation_delete_time_valid(d->'start') THEN RETURN false;END IF;
   IF kind<>'schedule_on_call_history' OR d->'end'<>'null' THEN
    IF NOT public.schedule_rotation_delete_time_valid(d->'end') OR (d->>'end')::timestamptz<=(d->>'start')::timestamptz THEN RETURN false;END IF;
   END IF;
  END IF;
 END LOOP;
 IF EXISTS(SELECT FROM jsonb_array_elements(effects) child WHERE child->>'resource_type'='fixed_shift' AND NOT EXISTS(
  SELECT FROM jsonb_array_elements(effects) t WHERE t->>'resource_type'='temporary_schedule' AND t#>>'{event_time_identity,envelope_id}'=child#>>'{event_time_identity,envelope_id}' AND t#>>'{event_time_identity,ordinal}'=child#>>'{event_time_identity,parent_ordinal}' AND (child#>>'{shift,start}')::timestamptz>=(t#>>'{temporary,start}')::timestamptz AND (child#>>'{shift,end}')::timestamptz<=(t#>>'{temporary,end}')::timestamptz)) THEN RETURN false;END IF;
 IF (SELECT count(*) FROM jsonb_array_elements(effects) WHERE value->>'resource_type'='on_call_notification_rule')<>(SELECT count(DISTINCT (value#>>'{on_call_rule,local_id}')::integer) FROM jsonb_array_elements(effects) WHERE value->>'resource_type'='on_call_notification_rule') THEN RETURN false;END IF;
 IF state<>'null' THEN
  expected=ARRAY['id','participant_id','position','version','shift_start'];
  IF typ<>'rotation' OR jsonb_typeof(state)<>'object' OR NOT(state ?& expected) OR (SELECT count(*) FROM jsonb_object_keys(state))<>5 THEN RETURN false;END IF;
  FOREACH k IN ARRAY ARRAY['id','position','version'] LOOP IF jsonb_typeof(state->k)<>'number' OR state->>k !~ '^[0-9]+$' THEN RETURN false;END IF;END LOOP;
  IF (state->>'id')::bigint<=0 OR (state->>'position')::integer<0 OR (state->>'version')::integer<1 OR jsonb_typeof(state->'participant_id')<>'string' OR NOT public.schedule_rotation_delete_time_valid(state->'shift_start') THEN RETURN false;END IF;
  IF NOT EXISTS(SELECT FROM jsonb_array_elements(effects) child WHERE child->>'resource_type'='rotation_participant' AND (child->>'resource_uuid')::uuid=(state->>'participant_id')::uuid AND (child#>>'{participant,position}')::integer=(state->>'position')::integer) THEN RETURN false;END IF;
 END IF;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;

-- D09-SD6: explicit Schedule/Rotation and closed historical B2 effects. No live FK.
CREATE TABLE schedule_rotation_delete_audit_events (
  schema_version smallint NOT NULL DEFAULT 1 CHECK(schema_version=1),
  event_id uuid PRIMARY KEY CHECK(event_id<>'00000000-0000-0000-0000-000000000000'),
  request_id uuid NOT NULL CHECK(request_id<>'00000000-0000-0000-0000-000000000000'),
  execution_id uuid NOT NULL CHECK(execution_id<>'00000000-0000-0000-0000-000000000000'),
  attempt_id uuid NOT NULL CHECK(attempt_id<>'00000000-0000-0000-0000-000000000000'),
  record_kind text NOT NULL CHECK(record_kind IN ('success_witness','attempt_observation')),
  operation text NOT NULL CHECK(operation=root_type||'.delete'),
  root_type text NOT NULL CHECK(root_type IN ('schedule','rotation')),
  root_id uuid CHECK(root_id<>'00000000-0000-0000-0000-000000000000'),
  target_organization_id uuid CHECK(target_organization_id<>'00000000-0000-0000-0000-000000000000'),
  target_org_resolution text NOT NULL,
  effects_version smallint NOT NULL DEFAULT 1 CHECK(effects_version=1),
  effects jsonb NOT NULL DEFAULT '[]'::jsonb,
  before_state jsonb NOT NULL DEFAULT 'null'::jsonb,
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
  CHECK (schedule_rotation_delete_effects_valid(effects,before_state,root_id,target_organization_id,root_type,actor_kind='human')),
  CHECK (record_kind='success_witness' OR (effects='[]'::jsonb AND before_state='null'::jsonb)),
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
CREATE UNIQUE INDEX schedule_rotation_delete_success_target ON schedule_rotation_delete_audit_events(attempt_id,root_type,root_id) WHERE record_kind='success_witness';
CREATE INDEX schedule_rotation_delete_correlation ON schedule_rotation_delete_audit_events(request_id,execution_id,attempt_id);
CREATE INDEX schedule_rotation_delete_root ON schedule_rotation_delete_audit_events(root_type,root_id,occurred_at,event_id);
CREATE INDEX schedule_rotation_delete_org ON schedule_rotation_delete_audit_events(target_organization_id,occurred_at,event_id);
CREATE INDEX schedule_rotation_delete_actor ON schedule_rotation_delete_audit_events(actor_id,occurred_at,event_id);
CREATE FUNCTION schedule_rotation_delete_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='schedule/rotation.delete audit is append-only';
END;
$$;
CREATE TRIGGER schedule_rotation_delete_no_change BEFORE UPDATE OR DELETE ON schedule_rotation_delete_audit_events
FOR EACH ROW EXECUTE FUNCTION schedule_rotation_delete_append_only();
CREATE TRIGGER schedule_rotation_delete_no_truncate BEFORE TRUNCATE ON schedule_rotation_delete_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION schedule_rotation_delete_append_only();
REVOKE ALL ON schedule_rotation_delete_audit_events FROM PUBLIC;
REVOKE ALL ON FUNCTION schedule_rotation_delete_append_only() FROM PUBLIC;

REVOKE ALL ON FUNCTION schedule_rotation_delete_effects_valid(jsonb,jsonb,uuid,uuid,text,boolean) FROM PUBLIC;

REVOKE ALL ON FUNCTION schedule_rotation_delete_time_valid(jsonb) FROM PUBLIC;

-- +migrate Down
DO $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='schedule/rotation.delete audit downgrade refused: preserve audit history';
END;
$$;
