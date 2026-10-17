-- Flyway creates its configured auth schema before running this transaction.
-- ALTER TABLE SET SCHEMA preserves rows, constraints, and associated indexes.
DO $$
BEGIN
    IF to_regclass('"${legacySchema}".auth_users') IS NOT NULL THEN
        IF to_regclass('"${flyway:defaultSchema}".auth_users') IS NOT NULL THEN
            RAISE EXCEPTION 'Both legacy and target auth_users exist; refusing to overwrite data';
        END IF;
        ALTER TABLE "${legacySchema}".auth_users SET SCHEMA "${flyway:defaultSchema}";
    END IF;
    IF to_regclass('"${legacySchema}".auth_sessions') IS NOT NULL THEN
        IF to_regclass('"${flyway:defaultSchema}".auth_sessions') IS NOT NULL THEN
            RAISE EXCEPTION 'Both legacy and target auth_sessions exist; refusing to overwrite data';
        END IF;
        ALTER TABLE "${legacySchema}".auth_sessions SET SCHEMA "${flyway:defaultSchema}";
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS "${flyway:defaultSchema}".auth_users (
    id UUID PRIMARY KEY,
    email VARCHAR(254) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(255) NOT NULL,
    failed_attempts INTEGER NOT NULL,
    locked_until TIMESTAMP(6) WITH TIME ZONE
);
CREATE TABLE IF NOT EXISTS "${flyway:defaultSchema}".auth_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    refresh_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    revoked BOOLEAN NOT NULL
);
