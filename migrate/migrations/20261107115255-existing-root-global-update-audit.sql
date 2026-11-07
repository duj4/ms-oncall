-- +migrate Up

-- D02-S1-A1-F01: Home is attribution. A trusted PlatformAdmin may manage an
-- existing Root in another Normal Organization. Ordinary OrgAdmin remains
-- Home-scoped. All other audit constraints and append-only history are retained.
ALTER TABLE schedule_rotation_update_audit_events
    DROP CONSTRAINT schedule_rotation_update_audit_events_check4,
    ADD CONSTRAINT schedule_rotation_update_audit_events_check4 CHECK (
        outcome <> 'committed' OR (
            target_id IS NOT NULL AND actor_kind <> 'unknown'
            AND (actor_kind <> 'human' OR authority_role = 'platform_admin'
                OR (authority_role = 'org_admin' AND home_organization_id = target_organization_id))
        )
    );

-- +migrate Down

-- Accepted foreign-target audit history cannot be deleted or rewritten to fit
-- the previous Home-only constraint. Retain the existing no-destructive-down policy.
DO $$
BEGIN
    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='global existing-root audit downgrade refused: preserve audit history';
END;
$$;
