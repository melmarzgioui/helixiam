-- Trusted lists: HMAC-SHA256 (keyed from DB_ENCRYPTION) of the rows that decide trust. settings_mac covers a source's
-- URL, format, pinned signers, service types, statuses and territories; services_mac the verified services (with
-- sequence number and NextUpdate) of a source or a member. A row whose MAC does not match is not used. Null when the
-- server runs without DB_ENCRYPTION (dev only).
ALTER TABLE trusted_list_source ADD COLUMN IF NOT EXISTS settings_mac character varying(64);
ALTER TABLE trusted_list_source ADD COLUMN IF NOT EXISTS services_mac character varying(64);
ALTER TABLE trusted_list_member ADD COLUMN IF NOT EXISTS services_mac character varying(64);
