-- name: ScheduleFindManyByUser :many
SELECT
    *
FROM
    schedules
WHERE
    id = ANY (
        SELECT
            schedule_id
        FROM
            schedule_rules
        WHERE
            tgt_user_id = $1
            OR tgt_rotation_id = ANY (
                SELECT
                    rotation_id
                FROM
                    rotation_participants
                WHERE
                    user_id = $1));

-- name: ScheduleFindManyByUserScoped :many
SELECT
    *
FROM
    schedules
WHERE
    organization_id = $2
    AND id = ANY (
        SELECT
            schedule_id
        FROM
            schedule_rules
        WHERE
            tgt_user_id = $1
            OR tgt_rotation_id = ANY (
                SELECT
                    rotation_id
                FROM
                    rotation_participants
                WHERE
                    user_id = $1));

-- name: SchedCheckOrganization :one
SELECT 1
FROM schedules
WHERE id = sqlc.arg(schedule_id)
  AND organization_id = sqlc.arg(organization_id);

-- name: SchedFindData :one
-- Returns the schedule data for a given schedule ID.
SELECT
    data
FROM
    schedule_data
WHERE
    schedule_id = $1;

-- name: SchedFindDataForUpdate :one
-- Returns the schedule data for a given schedule ID with FOR UPDATE lock.
SELECT
    data
FROM
    schedule_data
WHERE
    schedule_id = $1
FOR UPDATE;

-- name: SchedInsertData :exec
-- Inserts empty schedule data for a given schedule ID.
INSERT INTO schedule_data (schedule_id, data)
VALUES ($1, '{}');

-- name: SchedUpdateData :exec
-- Updates the schedule data for a given schedule ID.
UPDATE schedule_data
SET data = $2
WHERE schedule_id = $1;

-- name: SchedCreate :one
-- Creates a new schedule and returns its ID.
INSERT INTO schedules (id, organization_id, name, description, time_zone)
VALUES (DEFAULT, $1, $2, $3, $4)
RETURNING id;

-- name: SchedUpdate :exec
-- Updates an existing schedule.
UPDATE schedules
SET name = $2, description = $3, time_zone = $4
WHERE id = $1;

-- name: SchedUpdateScoped :execrows
UPDATE schedules
SET name = $2, description = $3, time_zone = $4
WHERE id = $1 AND organization_id = $5;

-- name: SchedFindAll :many
-- Returns all schedules.
SELECT id, organization_id, name, description, time_zone
FROM schedules;

-- name: SchedFindOne :one
-- Returns a single schedule with user favorite status.
SELECT
    s.id,
    s.organization_id,
    s.name,
    s.description,
    s.time_zone,
    fav IS DISTINCT FROM NULL as is_favorite
FROM schedules s
LEFT JOIN user_favorites fav ON
    fav.tgt_schedule_id = s.id AND fav.user_id = $2
WHERE s.id = $1;

-- name: SchedFindOneScoped :one
-- Returns a single Organization-scoped schedule with user favorite status.
SELECT
    s.id,
    s.organization_id,
    s.name,
    s.description,
    s.time_zone,
    fav IS DISTINCT FROM NULL as is_favorite
FROM schedules s
LEFT JOIN user_favorites fav ON
    fav.tgt_schedule_id = s.id AND fav.user_id = $2
WHERE s.id = $1 AND s.organization_id = $3;

-- name: SchedFindOneForUpdate :one
-- Returns a single schedule with FOR UPDATE lock.
SELECT id, organization_id, name, description, time_zone
FROM schedules
WHERE id = $1
FOR UPDATE;

-- name: SchedFindOneForUpdateScoped :one
-- Returns one Organization-scoped schedule with FOR UPDATE lock.
SELECT id, organization_id, name, description, time_zone
FROM schedules
WHERE id = $1 AND organization_id = $2
FOR UPDATE;

-- name: SchedFindMany :many
-- Returns multiple schedules with user favorite status.
SELECT
    s.id,
    s.organization_id,
    s.name,
    s.description,
    s.time_zone,
    fav IS DISTINCT FROM NULL as is_favorite
FROM schedules s
LEFT JOIN user_favorites fav ON
    fav.tgt_schedule_id = s.id AND fav.user_id = $2
WHERE s.id = ANY($1::uuid[]);

-- name: SchedFindManyScoped :many
-- Returns multiple Organization-scoped schedules with user favorite status.
SELECT
    s.id,
    s.organization_id,
    s.name,
    s.description,
    s.time_zone,
    fav IS DISTINCT FROM NULL as is_favorite
FROM schedules s
LEFT JOIN user_favorites fav ON
    fav.tgt_schedule_id = s.id AND fav.user_id = $2
WHERE s.id = ANY($1::uuid[]) AND s.organization_id = $3;

-- name: SchedDeleteMany :exec
-- Deletes multiple schedules by their IDs.
DELETE FROM schedules
WHERE id = ANY($1::uuid[]);

-- name: SchedDeleteManyScoped :execrows
-- Deletes every distinct requested ID only when all belong to one Organization.
DELETE FROM schedules sched
WHERE sched.id = ANY($1::uuid[])
    AND sched.organization_id = $2
    AND (
        SELECT count(*)
        FROM (
            SELECT DISTINCT requested_id
            FROM unnest($1::uuid[]) AS requested(requested_id)
        ) requested
    ) = (
        SELECT count(*)
        FROM schedules matched
        WHERE matched.id = ANY($1::uuid[])
            AND matched.organization_id = $2
    );
