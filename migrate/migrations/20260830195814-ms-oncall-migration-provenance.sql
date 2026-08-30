-- +migrate Up

CREATE TABLE ms_oncall_migration_provenance (
    canonical_position bigint PRIMARY KEY CHECK (canonical_position > 0),
    migration_id text NOT NULL UNIQUE,
    migration_name text NOT NULL UNIQUE,
    provenance_class text NOT NULL CHECK (provenance_class IN ('UPSTREAM_GOALERT', 'MS_ONCALL')),
    original_migration_id text NOT NULL,
    content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    source_binding text NOT NULL CHECK (source_binding <> ''),
    bundle_id text NOT NULL CHECK (bundle_id <> ''),
    predecessor_migration_id text REFERENCES ms_oncall_migration_provenance (migration_id),
    dependency_evidence text NOT NULL CHECK (dependency_evidence <> ''),
    adaptation_evidence text NOT NULL CHECK (adaptation_evidence <> ''),
    record_origin text NOT NULL CHECK (record_origin IN ('LEGACY_GORP_BOOTSTRAP', 'CANONICAL_EXECUTION')),
    applied_at timestamp with time zone,
    recorded_at timestamp with time zone NOT NULL DEFAULT now(),
    UNIQUE (provenance_class, source_binding, original_migration_id),
    CHECK ((canonical_position = 1) = (predecessor_migration_id IS NULL))
);

-- +migrate Down

DROP TABLE ms_oncall_migration_provenance;
