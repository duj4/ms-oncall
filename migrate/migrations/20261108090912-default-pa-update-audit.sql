-- +migrate Up

-- Home remains event-time attribution. Only the precise Default PA / NONE
-- combination is added. Existing history and all other constraints remain.
ALTER TABLE service_update_audit_events
  DROP CONSTRAINT service_update_audit_events_organization_role_check,
  ADD CONSTRAINT service_update_audit_events_organization_role_check
    CHECK (organization_role IN ('ORG_ADMIN','ORG_MEMBER','NONE','unknown')),
  DROP CONSTRAINT service_update_audit_events_check2,
  ADD CONSTRAINT service_update_audit_events_check2 CHECK (
    (actor_kind='human' AND actor_id IS NOT NULL AND home_organization_id IS NOT NULL
      AND authority_source='current_local_user_organization_at_admission'
      AND ((organization_role IN ('ORG_ADMIN','ORG_MEMBER')
        AND (authority_role='platform_admin' OR (authority_role='org_admin' AND organization_role='ORG_ADMIN') OR (authority_role='org_member' AND organization_role='ORG_MEMBER')))
      OR (organization_role='NONE' AND authority_role='platform_admin'
        AND home_organization_id='296e2656-7221-53fe-bd0a-832d24ccfd03'
        AND (target_organization_id IS NULL OR target_organization_id NOT IN
          ('296e2656-7221-53fe-bd0a-832d24ccfd03','00000000-0000-0000-0000-000000000000')))))
    OR (actor_kind='internal_system' AND actor_id IS NULL AND home_organization_id IS NULL
      AND authority_source='trusted_internal_system' AND authority_role='internal_system' AND organization_role='unknown')
    OR (actor_kind='unknown' AND actor_id IS NULL AND home_organization_id IS NULL
      AND authority_source='unknown' AND authority_role='unknown' AND organization_role='unknown')
  );

ALTER TABLE schedule_rotation_update_audit_events
  DROP CONSTRAINT schedule_rotation_update_audit_events_organization_role_check,
  ADD CONSTRAINT schedule_rotation_update_audit_events_organization_role_check
    CHECK (organization_role IN ('ORG_ADMIN','ORG_MEMBER','NONE','unknown')),
  DROP CONSTRAINT schedule_rotation_update_audit_events_check3,
  ADD CONSTRAINT schedule_rotation_update_audit_events_check3 CHECK (
    (actor_kind='human' AND actor_id IS NOT NULL AND home_organization_id IS NOT NULL
      AND authority_source='current_local_user_organization_at_admission'
      AND ((organization_role IN ('ORG_ADMIN','ORG_MEMBER')
        AND (authority_role='platform_admin' OR (authority_role='org_admin' AND organization_role='ORG_ADMIN') OR (authority_role='org_member' AND organization_role='ORG_MEMBER')))
      OR (organization_role='NONE' AND authority_role='platform_admin'
        AND home_organization_id='296e2656-7221-53fe-bd0a-832d24ccfd03'
        AND (target_organization_id IS NULL OR target_organization_id NOT IN
          ('296e2656-7221-53fe-bd0a-832d24ccfd03','00000000-0000-0000-0000-000000000000')))))
    OR (actor_kind='internal_system' AND actor_id IS NULL AND home_organization_id IS NULL
      AND authority_source='trusted_internal_system' AND authority_role='internal_system' AND organization_role='unknown')
    OR (actor_kind='unknown' AND actor_id IS NULL AND home_organization_id IS NULL AND target_id IS NULL
      AND authority_source='unknown' AND authority_role='unknown' AND organization_role='unknown')
  );

-- +migrate Down
DO $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Default PA audit downgrade refused: preserve audit history';
END;
$$;
