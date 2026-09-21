-- name: LabelUniqueKeys :many
SELECT DISTINCT
    key
FROM
    labels l
WHERE
    sqlc.narg(organization_id)::uuid IS NULL
    OR EXISTS (SELECT 1 FROM services s WHERE s.id = l.tgt_service_id AND s.organization_id = sqlc.narg(organization_id));

-- name: LabelFindAllByTarget :many
SELECT
    key,
    value
FROM
    labels l
WHERE
    tgt_service_id = @tgt_service_id
    AND (sqlc.narg(organization_id)::uuid IS NULL
        OR EXISTS (SELECT 1 FROM services s WHERE s.id = l.tgt_service_id AND s.organization_id = sqlc.narg(organization_id)));

-- name: LabelCheckServiceOrganization :one
SELECT organization_id = @organization_id AS allowed
FROM services
WHERE id = @id;

-- name: LabelDeleteKeyByTarget :exec
DELETE FROM labels
WHERE key = $1
    AND tgt_service_id = $2;

-- name: LabelSetByTarget :exec
INSERT INTO labels(key, value, tgt_service_id)
    VALUES ($1, $2, $3)
ON CONFLICT (key, tgt_service_id)
    DO UPDATE SET
        value = $2;
