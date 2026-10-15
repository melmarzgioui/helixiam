-- Trusted lists: HMAC-SHA256 (keyed from DB_ENCRYPTION) of the rows that decide trust. settings_mac covers a source's
-- URL, format, pinned signers, service types, statuses and territories; services_mac the verified services (with
-- sequence number and NextUpdate) of a source or a member. A row whose MAC does not match is not used. Null when the
-- server runs without DB_ENCRYPTION (dev only). With DB_ENCRYPTION set, a NULL MAC is an integrity failure like a wrong
-- one: rows stored before this migration are never adopted (settings: an admin saves them again; anchors: reloaded).
ALTER TABLE trusted_list_source ADD COLUMN IF NOT EXISTS settings_mac character varying(64);
ALTER TABLE trusted_list_source ADD COLUMN IF NOT EXISTS services_mac character varying(64);
ALTER TABLE trusted_list_member ADD COLUMN IF NOT EXISTS services_mac character varying(64);
-- The member list's own TSLType, so a member row below its territory's high-water mark is not counted.
ALTER TABLE trusted_list_member ADD COLUMN IF NOT EXISTS tsl_type character varying(255);
-- Rollback high-water marks of the members of a list of trusted lists: the highest sequence number accepted per
-- territory and TSLType. They outlive the member rows (a list that moves to another URL, or is dropped and pointed at
-- again, cannot come back older) and are MACed like the anchors.
CREATE TABLE IF NOT EXISTS trusted_list_hwm (
    source_id       character varying(36)  NOT NULL REFERENCES trusted_list_source (id) ON DELETE CASCADE,
    territory       character varying(16)  NOT NULL,
    tsl_type        character varying(255) NOT NULL,
    sequence_number bigint                 NOT NULL,
    mac             character varying(64),
    PRIMARY KEY (source_id, territory, tsl_type)
);
