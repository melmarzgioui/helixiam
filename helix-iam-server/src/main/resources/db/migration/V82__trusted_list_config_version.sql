-- Trusted lists: config_version moves on every settings change, so a refresh that started under older settings
-- (other URL, other pinned signers) can no longer store its result: recordSuccess/recordFailure require the
-- config_version the refresh read when it took the lease.
ALTER TABLE trusted_list_source ADD COLUMN IF NOT EXISTS config_version bigint NOT NULL DEFAULT 1;
