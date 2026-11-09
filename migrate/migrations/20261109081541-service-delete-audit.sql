-- +migrate Up

-- D09-SD1: explicit Service targets in GraphQL DeleteAll only. LOGGED by
-- default, no business FKs, input text, credentials or raw destinations.
CREATE TABLE service_delete_audit_events (
  schema_version smallint NOT NULL DEFAULT 1 CHECK (schema_version=1),
  event_id uuid PRIMARY KEY CHECK (event_id<>'00000000-0000-0000-0000-000000000000'),
  attempt_id uuid NOT NULL CHECK (attempt_id<>'00000000-0000-0000-0000-000000000000'),
  request_id uuid NOT NULL CHECK (request_id<>'00000000-0000-0000-0000-000000000000'),
  operation text NOT NULL DEFAULT 'service.delete' CHECK (operation='service.delete'),
  actor_kind text NOT NULL CHECK (actor_kind IN ('human','internal_system','unknown')),
  actor_id uuid CHECK (actor_id<>'00000000-0000-0000-0000-000000000000'),
  home_organization_id uuid CHECK (home_organization_id<>'00000000-0000-0000-0000-000000000000'),
  authority_source text NOT NULL,
  authority_role text NOT NULL,
  organization_role text NOT NULL,
  service_id uuid CHECK (service_id<>'00000000-0000-0000-0000-000000000000'),
  target_organization_id uuid CHECK (target_organization_id NOT IN ('00000000-0000-0000-0000-000000000000','296e2656-7221-53fe-bd0a-832d24ccfd03')),
  outcome text NOT NULL,
  reason_code text NOT NULL,
  occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((service_id IS NULL)=(target_organization_id IS NULL)),
  CHECK ((outcome='committed' AND reason_code='deleted')
    OR (outcome='denied' AND reason_code='authority_denied')
    OR (outcome='validation_failed' AND reason_code IN ('invalid_fields','target_unavailable'))
    OR (outcome='tx_failed' AND reason_code IN ('begin_failed','write_failed','audit_write_failed','commit_rejected'))
    OR (outcome='commit_unknown' AND reason_code='commit_unconfirmed')
    OR (outcome='rollback_unconfirmed' AND reason_code='rollback_unconfirmed')),
  CHECK ((actor_kind='human' AND actor_id IS NOT NULL AND home_organization_id IS NOT NULL
      AND authority_source='current_local_user_organization_at_admission'
      AND ((home_organization_id='296e2656-7221-53fe-bd0a-832d24ccfd03' AND organization_role='NONE' AND authority_role IN ('platform_admin','none'))
        OR (home_organization_id<>'296e2656-7221-53fe-bd0a-832d24ccfd03' AND organization_role IN ('ORG_ADMIN','ORG_MEMBER')
          AND (authority_role='platform_admin' OR (authority_role='org_admin' AND organization_role='ORG_ADMIN') OR (authority_role='org_member' AND organization_role='ORG_MEMBER')))))
    OR (actor_kind='internal_system' AND actor_id IS NULL AND home_organization_id IS NULL
      AND authority_source='trusted_internal_system' AND authority_role='internal_system' AND organization_role='unknown')
    OR (actor_kind='unknown' AND actor_id IS NULL AND home_organization_id IS NULL
      AND authority_source='unknown' AND authority_role='unknown' AND organization_role='unknown')),
  CHECK (outcome<>'committed' OR (service_id IS NOT NULL AND actor_kind<>'unknown'
    AND (actor_kind='internal_system' OR authority_role='platform_admin'
      OR (authority_role='org_admin' AND home_organization_id=target_organization_id))))
);

CREATE INDEX service_delete_audit_request_attempt ON service_delete_audit_events(request_id,attempt_id);
CREATE INDEX service_delete_audit_service ON service_delete_audit_events(service_id,occurred_at);
CREATE UNIQUE INDEX service_delete_audit_committed_target ON service_delete_audit_events(attempt_id,service_id) WHERE outcome='committed';

CREATE FUNCTION service_delete_audit_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='service.delete audit history is append-only';
END;
$$;
CREATE TRIGGER service_delete_audit_no_rewrite
BEFORE UPDATE OR DELETE OR TRUNCATE ON service_delete_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION service_delete_audit_append_only();
REVOKE ALL ON service_delete_audit_events FROM PUBLIC;
REVOKE ALL ON FUNCTION service_delete_audit_append_only() FROM PUBLIC;

-- +migrate Down
DO $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='service.delete audit downgrade refused: preserve audit history';
END;
$$;
