-- +migrate Up

-- D09-A1: application-level append-only history for exactly service.update.
-- No business-resource FK: deleting a Service/User/Organization must not erase
-- or rewrite event-time attribution. No input values or credential references.
CREATE TABLE service_update_audit_events (
	 schema_version smallint NOT NULL DEFAULT 1 CHECK (schema_version = 1),
    event_id uuid PRIMARY KEY CHECK (event_id <> '00000000-0000-0000-0000-000000000000'),
    attempt_id uuid NOT NULL CHECK (attempt_id <> '00000000-0000-0000-0000-000000000000'),
    request_id uuid NOT NULL CHECK (request_id <> '00000000-0000-0000-0000-000000000000'),
    operation text NOT NULL DEFAULT 'service.update' CHECK (operation = 'service.update'),
    actor_kind text NOT NULL CHECK (actor_kind IN ('human', 'internal_system', 'unknown')),
    actor_id uuid,
    home_organization_id uuid,
    authority_source text NOT NULL CHECK (authority_source IN ('current_local_user_organization_at_admission', 'trusted_internal_system', 'unknown')),
    authority_role text NOT NULL CHECK (authority_role IN ('platform_admin', 'org_admin', 'org_member', 'internal_system', 'unknown')),
    organization_role text NOT NULL CHECK (organization_role IN ('ORG_ADMIN', 'ORG_MEMBER', 'unknown')),
    service_id uuid,
    target_organization_id uuid,
    requested_fields smallint NOT NULL CHECK (requested_fields BETWEEN 0 AND 15),
    outcome text NOT NULL CHECK (outcome IN ('committed', 'denied', 'validation_failed', 'tx_failed', 'commit_unknown', 'rollback_unconfirmed')),
    reason_code text NOT NULL CHECK (reason_code IN ('updated', 'authority_denied', 'target_unavailable', 'invalid_fields', 'begin_failed', 'write_failed', 'audit_write_failed', 'commit_rejected', 'commit_unconfirmed', 'rollback_unconfirmed')),
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((service_id IS NULL) = (target_organization_id IS NULL)),
    CHECK (outcome <> 'committed' OR (service_id IS NOT NULL AND actor_kind <> 'unknown' AND reason_code = 'updated')),
    CHECK (
        (actor_kind = 'human' AND actor_id IS NOT NULL AND home_organization_id IS NOT NULL
            AND authority_source = 'current_local_user_organization_at_admission'
            AND organization_role IN ('ORG_ADMIN', 'ORG_MEMBER')
            AND (authority_role = 'platform_admin' OR (authority_role = 'org_admin' AND organization_role = 'ORG_ADMIN') OR (authority_role = 'org_member' AND organization_role = 'ORG_MEMBER')))
        OR (actor_kind = 'internal_system' AND actor_id IS NULL AND home_organization_id IS NULL
            AND authority_source = 'trusted_internal_system' AND authority_role = 'internal_system' AND organization_role = 'unknown')
        OR (actor_kind = 'unknown' AND actor_id IS NULL AND home_organization_id IS NULL
            AND authority_source = 'unknown' AND authority_role = 'unknown' AND organization_role = 'unknown')
    )
);

CREATE INDEX service_update_audit_attempt ON service_update_audit_events (attempt_id);

CREATE FUNCTION service_update_audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'service.update audit history is append-only';
END;
$$;

CREATE TRIGGER service_update_audit_no_rewrite
BEFORE UPDATE OR DELETE OR TRUNCATE ON service_update_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION service_update_audit_append_only();

-- +migrate Down

-- Binary rollback must preserve audit history and its schema. Production
-- retention/removal requires a separately owner-approved maintenance task.
DO $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'service.update audit downgrade refused: preserve audit history';
END;
$$;
