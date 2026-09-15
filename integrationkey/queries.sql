-- name: IntKeyGetServiceID :one
SELECT
    service_id
FROM
    integration_keys
WHERE
    id = $1
    AND type = $2;

-- name: IntKeyCreate :exec
INSERT INTO integration_keys(id, name, type, service_id, external_system_name)
    VALUES ($1, $2, $3, $4, $5);

-- name: IntKeyFindOne :one
SELECT
    integration_keys.id,
    integration_keys.name,
    integration_keys.type,
    integration_keys.service_id,
    integration_keys.external_system_name
FROM
    integration_keys
WHERE
    integration_keys.id = $1
    AND (sqlc.narg(organization_id)::uuid IS NULL
        OR EXISTS (SELECT 1 FROM services s
            WHERE s.id = integration_keys.service_id AND s.organization_id = sqlc.narg(organization_id)));

-- name: IntKeyFindByService :many
SELECT
    integration_keys.id,
    integration_keys.name,
    integration_keys.type,
    integration_keys.service_id,
    integration_keys.external_system_name
FROM
    integration_keys
WHERE
    integration_keys.service_id = $1
    AND (sqlc.narg(organization_id)::uuid IS NULL
        OR EXISTS (SELECT 1 FROM services s
            WHERE s.id = integration_keys.service_id AND s.organization_id = sqlc.narg(organization_id)));

-- name: IntKeyDelete :exec
DELETE FROM integration_keys
WHERE id = ANY (@ids::uuid[]);

-- name: IntKeyCheckServiceOrganization :one
SELECT id FROM services
WHERE id = @service_id AND organization_id = @organization_id;

-- name: IntKeyCheckOrganization :one
SELECT k.id FROM integration_keys k
JOIN services s ON s.id = k.service_id
WHERE k.id = @id AND s.organization_id = @organization_id;

-- name: IntKeyDeleteOrganization :execrows
DELETE FROM integration_keys k
USING services s
WHERE k.id = ANY (@ids::uuid[])
    AND s.id = k.service_id AND s.organization_id = @organization_id
    AND (SELECT count(DISTINCT requested_id) FROM unnest(@ids::uuid[]) AS requested(requested_id)) = (
        SELECT count(*) FROM integration_keys matched
        JOIN services parent ON parent.id = matched.service_id
        WHERE matched.id = ANY (@ids::uuid[]) AND parent.organization_id = @organization_id
    );

-- name: IntKeyGetConfig :one
SELECT
    config
FROM
    uik_config
WHERE
    id = $1
FOR UPDATE;

-- name: IntKeySetConfig :exec
INSERT INTO uik_config(id, config)
    VALUES ($1, $2)
ON CONFLICT (id)
    DO UPDATE SET
        config = $2;

-- name: IntKeyDeleteConfig :exec
DELETE FROM uik_config
WHERE id = $1;

-- name: IntKeyGetType :one
SELECT
    type
FROM
    integration_keys
WHERE
    id = $1;

-- name: IntKeyPromoteSecondary :one
UPDATE
    uik_config
SET
    primary_token = secondary_token,
    primary_token_hint = secondary_token_hint,
    secondary_token = NULL,
    secondary_token_hint = NULL
WHERE
    id = $1
RETURNING
    primary_token_hint;

-- name: IntKeyTokenHints :one
SELECT
    primary_token_hint,
    secondary_token_hint
FROM
    uik_config
WHERE
    id = $1;

-- name: IntKeySetPrimaryToken :one
UPDATE
    uik_config
SET
    primary_token = $2,
    primary_token_hint = $3
WHERE
    id = $1
    AND primary_token IS NULL
RETURNING
    id;

-- name: IntKeySetSecondaryToken :one
UPDATE
    uik_config
SET
    secondary_token = $2,
    secondary_token_hint = $3
WHERE
    id = $1
    AND secondary_token IS NULL
    AND primary_token IS NOT NULL
RETURNING
    id;

-- name: IntKeyUIKValidateService :one
SELECT
    k.service_id
FROM
    uik_config c
    JOIN integration_keys k ON k.id = c.id
WHERE
    c.id = sqlc.arg(key_id)
    AND k.type = 'universal'
    AND (c.primary_token = sqlc.arg(token_id)
        OR c.secondary_token = sqlc.arg(token_id));

-- name: IntKeyDeleteSecondaryToken :exec
UPDATE
    uik_config
SET
    secondary_token = NULL,
    secondary_token_hint = NULL
WHERE
    id = $1;

-- name: IntKeyInsertSignalMessage :exec
INSERT INTO pending_signals(dest_id, service_id, params)
    VALUES ($1, $2, $3);
