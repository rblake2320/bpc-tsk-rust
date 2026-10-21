-- Invoked only by the migrator inside a serializable, advisory-locked transaction.
CREATE SCHEMA IF NOT EXISTS bpc_tsk_bridge;
REVOKE ALL ON SCHEMA bpc_tsk_bridge FROM PUBLIC;
CREATE TABLE IF NOT EXISTS bpc_tsk_bridge.schema_version (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    version integer NOT NULL CHECK (version >= 0)
);
CREATE TABLE IF NOT EXISTS bpc_tsk_bridge.schema_migrations (
    version integer PRIMARY KEY CHECK (version > 0),
    checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO bpc_tsk_bridge.schema_version (singleton, version)
VALUES (true, 0) ON CONFLICT (singleton) DO NOTHING;
REVOKE ALL ON ALL TABLES IN SCHEMA bpc_tsk_bridge FROM PUBLIC;
