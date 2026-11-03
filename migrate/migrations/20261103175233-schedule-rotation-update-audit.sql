-- +migrate Up

-- D09-C4 S2: only schedule.update and rotation.update, no arbitrary JSON.
-- One logged row contains the header, target and all bounded effects atomically.
-- No business foreign keys: event-time history survives business deletion.
CREATE FUNCTION schedule_rotation_audit_snapshot_valid(
    ids uuid[], users uuid[], positions integer[], participant_count integer,
    state_id bigint, state_position integer, state_participant_id uuid,
    shift_start timestamptz, state_version integer
) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
SELECT CASE WHEN ids IS NULL THEN
    users IS NULL AND positions IS NULL AND participant_count IS NULL
    AND state_id IS NULL AND state_position IS NULL AND state_participant_id IS NULL
    AND shift_start IS NULL AND state_version IS NULL
ELSE COALESCE(
    users IS NOT NULL AND positions IS NOT NULL AND participant_count IS NOT NULL
    AND (cardinality(ids)=0 OR (array_ndims(ids)=1 AND array_lower(ids,1)=1))
    AND (cardinality(users)=0 OR (array_ndims(users)=1 AND array_lower(users,1)=1))
    AND (cardinality(positions)=0 OR (array_ndims(positions)=1 AND array_lower(positions,1)=1))
    AND cardinality(ids)=cardinality(users) AND cardinality(ids)=cardinality(positions)
    AND cardinality(ids)=participant_count
    AND NOT EXISTS (SELECT FROM unnest(ids) v WHERE v IS NULL OR v='00000000-0000-0000-0000-000000000000'::uuid)
    AND NOT EXISTS (SELECT FROM unnest(users) v WHERE v IS NULL OR v='00000000-0000-0000-0000-000000000000'::uuid)
    AND NOT EXISTS (SELECT FROM unnest(positions) v WHERE v IS NULL OR v<0)
    AND cardinality(ids)=(SELECT count(DISTINCT v) FROM unnest(ids) v)
    AND positions=ARRAY(SELECT DISTINCT v FROM unnest(positions) v ORDER BY v)
    AND ((state_id IS NULL AND state_position IS NULL AND state_participant_id IS NULL AND shift_start IS NULL AND state_version IS NULL)
        OR (state_id IS NOT NULL AND state_position IS NOT NULL AND state_participant_id IS NOT NULL
            AND shift_start IS NOT NULL AND state_version IS NOT NULL AND isfinite(shift_start)
            AND EXISTS (SELECT FROM unnest(ids,positions) p(id,pos) WHERE p.id=state_participant_id AND p.pos=state_position))), false)
END;
$$;

CREATE TABLE schedule_rotation_update_audit_events (
    schema_version smallint NOT NULL CHECK (schema_version=1),
    event_id uuid PRIMARY KEY CHECK (event_id<>'00000000-0000-0000-0000-000000000000'),
    attempt_id uuid NOT NULL CHECK (attempt_id<>'00000000-0000-0000-0000-000000000000'),
    request_id uuid NOT NULL CHECK (request_id<>'00000000-0000-0000-0000-000000000000'),
    operation text NOT NULL CHECK (operation IN ('schedule.update','rotation.update')),
    target_type text NOT NULL CHECK (target_type IN ('schedule','rotation')),
    actor_kind text NOT NULL CHECK (actor_kind IN ('human','internal_system','unknown')),
    actor_id uuid CHECK (actor_id<>'00000000-0000-0000-0000-000000000000'),
    home_organization_id uuid CHECK (home_organization_id<>'00000000-0000-0000-0000-000000000000'),
    authority_source text NOT NULL CHECK (authority_source IN ('current_local_user_organization_at_admission','trusted_internal_system','unknown')),
    authority_role text NOT NULL CHECK (authority_role IN ('platform_admin','org_admin','org_member','internal_system','unknown')),
    organization_role text NOT NULL CHECK (organization_role IN ('ORG_ADMIN','ORG_MEMBER','unknown')),
    target_id uuid CHECK (target_id<>'00000000-0000-0000-0000-000000000000'),
    target_organization_id uuid CHECK (target_organization_id<>'00000000-0000-0000-0000-000000000000'),
    requested_fields smallint NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('committed','denied','validation_failed','tx_failed','commit_unknown','rollback_unconfirmed')),
    reason_code text NOT NULL,
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    schedule_row_written boolean NOT NULL,
    rotation_row_written boolean NOT NULL,
    before_participant_ids uuid[],
    before_user_ids uuid[],
    before_positions integer[],
    before_participant_count integer,
    before_state_id bigint,
    before_state_position integer,
    before_state_participant_id uuid,
    before_shift_start timestamptz,
    before_state_version integer,
    after_participant_ids uuid[],
    after_user_ids uuid[],
    after_positions integer[],
    after_participant_count integer,
    after_state_id bigint,
    after_state_position integer,
    after_state_participant_id uuid,
    after_shift_start timestamptz,
    after_state_version integer,
    CHECK ((operation='schedule.update' AND target_type='schedule' AND requested_fields BETWEEN 0 AND 7)
        OR (operation='rotation.update' AND target_type='rotation' AND requested_fields BETWEEN 0 AND 255)),
    CHECK ((target_id IS NULL)=(target_organization_id IS NULL)),
    CHECK ((outcome='committed' AND reason_code='updated')
        OR (outcome='denied' AND reason_code IN ('authority_denied','target_unavailable'))
        OR (outcome='validation_failed' AND reason_code IN ('invalid_fields','target_unavailable'))
        OR (outcome='tx_failed' AND reason_code IN ('begin_failed','write_failed','audit_write_failed','commit_rejected'))
        OR (outcome='commit_unknown' AND reason_code='commit_unconfirmed')
        OR (outcome='rollback_unconfirmed' AND reason_code='rollback_unconfirmed')),
    CHECK ((actor_kind='human' AND actor_id IS NOT NULL AND home_organization_id IS NOT NULL
            AND authority_source='current_local_user_organization_at_admission'
            AND organization_role IN ('ORG_ADMIN','ORG_MEMBER')
            AND (authority_role='platform_admin' OR (authority_role='org_admin' AND organization_role='ORG_ADMIN') OR (authority_role='org_member' AND organization_role='ORG_MEMBER')))
        OR (actor_kind='internal_system' AND actor_id IS NULL AND home_organization_id IS NULL
            AND authority_source='trusted_internal_system' AND authority_role='internal_system' AND organization_role='unknown')
        OR (actor_kind='unknown' AND actor_id IS NULL AND home_organization_id IS NULL AND target_id IS NULL
            AND authority_source='unknown' AND authority_role='unknown' AND organization_role='unknown')),
    CHECK (outcome<>'committed' OR (target_id IS NOT NULL AND actor_kind<>'unknown'
        AND (actor_kind<>'human' OR (authority_role IN ('platform_admin','org_admin') AND home_organization_id=target_organization_id)))),
    CHECK (schedule_rotation_audit_snapshot_valid(
        before_participant_ids,before_user_ids,before_positions,before_participant_count,
        before_state_id,before_state_position,before_state_participant_id,before_shift_start,before_state_version)),
    CHECK (schedule_rotation_audit_snapshot_valid(
        after_participant_ids,after_user_ids,after_positions,after_participant_count,
        after_state_id,after_state_position,after_state_participant_id,after_shift_start,after_state_version)),
    CHECK ((outcome<>'committed' AND NOT schedule_row_written AND NOT rotation_row_written
                AND before_participant_ids IS NULL AND after_participant_ids IS NULL)
        OR (outcome='committed' AND operation='schedule.update' AND schedule_row_written AND NOT rotation_row_written
                AND before_participant_ids IS NULL AND after_participant_ids IS NULL)
        OR (outcome='committed' AND operation='rotation.update' AND NOT schedule_row_written
                AND rotation_row_written=((requested_fields & 63)<>0)
                AND before_participant_ids IS NOT NULL AND after_participant_ids IS NOT NULL))
);

CREATE INDEX schedule_rotation_update_audit_attempt ON schedule_rotation_update_audit_events (attempt_id);

CREATE FUNCTION schedule_rotation_audit_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='schedule/rotation update audit history is append-only';
END;
$$;
CREATE TRIGGER schedule_rotation_audit_no_rewrite
BEFORE UPDATE OR DELETE OR TRUNCATE ON schedule_rotation_update_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION schedule_rotation_audit_append_only();

REVOKE ALL ON schedule_rotation_update_audit_events FROM PUBLIC;
REVOKE ALL ON FUNCTION schedule_rotation_audit_snapshot_valid(uuid[],uuid[],integer[],integer,bigint,integer,uuid,timestamptz,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION schedule_rotation_audit_append_only() FROM PUBLIC;

-- +migrate Down

-- No destructive downgrade or retention policy is authorized by C4.
DO $$
BEGIN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='schedule/rotation update audit downgrade refused: preserve audit history';
END;
$$;
