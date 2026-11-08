-- +migrate Up

-- Only the four new top-level PA Create paths. No secrets, input text,
-- destinations, business FKs or unrelated product audit operation are stored.
CREATE TABLE global_root_create_audit_events (
  schema_version smallint NOT NULL DEFAULT 1 CHECK (schema_version=1),
  event_id uuid PRIMARY KEY CHECK (event_id<>'00000000-0000-0000-0000-000000000000'),
  attempt_id uuid NOT NULL CHECK (attempt_id<>'00000000-0000-0000-0000-000000000000'),
  request_id uuid NOT NULL CHECK (request_id<>'00000000-0000-0000-0000-000000000000'),
  actor_kind text NOT NULL DEFAULT 'human' CHECK (actor_kind='human'),
  actor_id uuid NOT NULL CHECK (actor_id<>'00000000-0000-0000-0000-000000000000'),
  authority_source text NOT NULL DEFAULT 'current_local_user_organization_at_admission'
    CHECK (authority_source='current_local_user_organization_at_admission'),
  authority_role text NOT NULL DEFAULT 'platform_admin' CHECK (authority_role='platform_admin'),
  home_organization_id uuid NOT NULL CHECK (home_organization_id<>'00000000-0000-0000-0000-000000000000'),
  organization_role text NOT NULL,
  root_type text NOT NULL CHECK (root_type IN ('service','escalation_policy','schedule','rotation')),
  operation text GENERATED ALWAYS AS (root_type || '.create') STORED,
  root_id uuid CHECK (root_id<>'00000000-0000-0000-0000-000000000000'),
  target_organization_id uuid CHECK (target_organization_id NOT IN ('00000000-0000-0000-0000-000000000000','296e2656-7221-53fe-bd0a-832d24ccfd03')),
  outcome text NOT NULL,
  reason_code text NOT NULL,
  occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((home_organization_id='296e2656-7221-53fe-bd0a-832d24ccfd03' AND organization_role='NONE')
    OR (home_organization_id<>'296e2656-7221-53fe-bd0a-832d24ccfd03' AND organization_role IN ('ORG_ADMIN','ORG_MEMBER'))),
  CHECK (root_id IS NULL OR target_organization_id IS NOT NULL),
  CHECK (outcome<>'committed' OR root_id IS NOT NULL),
  CHECK ((outcome='committed' AND reason_code='created')
    OR (outcome='denied' AND reason_code='authority_denied')
    OR (outcome='validation_failed' AND reason_code='invalid_fields')
    OR (outcome='tx_failed' AND reason_code='write_failed')
    OR (outcome='commit_unknown' AND reason_code='commit_unconfirmed')
    OR (outcome='rollback_unconfirmed' AND reason_code='rollback_unconfirmed'))
);
CREATE INDEX global_root_create_audit_attempt ON global_root_create_audit_events(attempt_id);
CREATE FUNCTION global_root_create_audit_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='global Root Create audit history is append-only';
END;
$$;
CREATE TRIGGER global_root_create_audit_no_rewrite
BEFORE UPDATE OR DELETE OR TRUNCATE ON global_root_create_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION global_root_create_audit_append_only();
REVOKE ALL ON global_root_create_audit_events FROM PUBLIC;
REVOKE ALL ON FUNCTION global_root_create_audit_append_only() FROM PUBLIC;

-- +migrate Down
DO $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='global Root Create audit downgrade refused: preserve audit history';
END;
$$;
