-- +migrate Up

-- D09-SD4: safe historical snapshots only. No credential projection or live FK.
CREATE TABLE integration_key_delete_audit_events (
  schema_version smallint NOT NULL DEFAULT 1 CHECK(schema_version=1),
  event_id uuid PRIMARY KEY CHECK(event_id<>'00000000-0000-0000-0000-000000000000'),
  request_id uuid NOT NULL CHECK(request_id<>'00000000-0000-0000-0000-000000000000'),
  execution_id uuid NOT NULL CHECK(execution_id<>'00000000-0000-0000-0000-000000000000'),
  attempt_id uuid NOT NULL CHECK(attempt_id<>'00000000-0000-0000-0000-000000000000'),
  record_kind text NOT NULL CHECK(record_kind IN ('success_witness','attempt_observation')),
  operation text NOT NULL DEFAULT 'integration_key.delete' CHECK(operation='integration_key.delete'),
  root_type text NOT NULL DEFAULT 'integration_key' CHECK(root_type='integration_key'),
  root_resource_id uuid CHECK(root_resource_id<>'00000000-0000-0000-0000-000000000000'),
  parent_service_id uuid CHECK(parent_service_id<>'00000000-0000-0000-0000-000000000000'),
  target_organization_id uuid CHECK(target_organization_id<>'00000000-0000-0000-0000-000000000000'),
  target_org_resolution text NOT NULL,
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
  occurred_at timestamptz NOT NULL CHECK(isfinite(occurred_at)),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(recorded_at)),
  CHECK (((root_resource_id IS NULL AND parent_service_id IS NULL AND target_organization_id IS NULL AND target_org_resolution='unknown')
    OR (root_resource_id IS NOT NULL AND parent_service_id IS NOT NULL AND target_organization_id IS NOT NULL AND (
      (target_org_resolution='known_normal' AND target_organization_id<>'296e2656-7221-53fe-bd0a-832d24ccfd03')
      OR (target_org_resolution='known_default' AND target_organization_id='296e2656-7221-53fe-bd0a-832d24ccfd03')))) IS TRUE),
  CHECK (((record_kind='success_witness' AND outcome='committed' AND reason_code='deleted' AND root_resource_id IS NOT NULL AND provenance='EXPLICIT' AND deletion_mechanism='explicit_sql' AND cause='explicit_target')
    OR (record_kind='attempt_observation' AND provenance IS NULL AND deletion_mechanism IS NULL AND cause IS NULL AND (
      (outcome='denied' AND reason_code='authority_denied')
      OR (outcome='validation_failed' AND reason_code IN ('invalid_fields','target_unavailable'))
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
CREATE UNIQUE INDEX integration_key_delete_success_target ON integration_key_delete_audit_events(attempt_id,root_resource_id) WHERE record_kind='success_witness';
CREATE INDEX integration_key_delete_correlation ON integration_key_delete_audit_events(request_id,execution_id,attempt_id);
CREATE INDEX integration_key_delete_root ON integration_key_delete_audit_events(root_resource_id,occurred_at,event_id);
CREATE INDEX integration_key_delete_org ON integration_key_delete_audit_events(target_organization_id,occurred_at,event_id);
CREATE INDEX integration_key_delete_actor ON integration_key_delete_audit_events(actor_id,occurred_at,event_id);
CREATE FUNCTION integration_key_delete_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='integration_key.delete audit is append-only';
END;
$$;
CREATE TRIGGER integration_key_delete_no_change BEFORE UPDATE OR DELETE ON integration_key_delete_audit_events
FOR EACH ROW EXECUTE FUNCTION integration_key_delete_append_only();
CREATE TRIGGER integration_key_delete_no_truncate BEFORE TRUNCATE ON integration_key_delete_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION integration_key_delete_append_only();
REVOKE ALL ON integration_key_delete_audit_events FROM PUBLIC;
REVOKE ALL ON FUNCTION integration_key_delete_append_only() FROM PUBLIC;

-- +migrate Down
DO $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='integration_key.delete audit downgrade refused: preserve audit history';
END;
$$;
