-- Trusted lists: the lists a list of trusted lists points at, each with its own state. A member keeps its own last
-- good services until its own NextUpdate plus the source's grace, is refused on its own (bad signature, rollback,
-- territory or type mismatch, plain http) and never blocks the others. member_key = SHA-256 of location and
-- territory. sequence_number is the last accepted list's; a lower one is refused (also in SQL). version moves on
-- every write of the row. list_of_lists marks a source whose anchors come from its members.
ALTER TABLE trusted_list_source ADD COLUMN IF NOT EXISTS list_of_lists boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS trusted_list_member (
    source_id       character varying(36)   NOT NULL REFERENCES trusted_list_source (id) ON DELETE CASCADE,
    member_key      character varying(64)   NOT NULL,
    location        character varying(2048) NOT NULL,
    territory       character varying(16),
    status          character varying(16)   NOT NULL,
    services_json   text,
    sequence_number bigint,
    list_issued_at  bigint,
    next_update     bigint,
    last_attempt_at bigint,
    last_success_at bigint,
    last_error      character varying(1000),
    version         bigint                  NOT NULL,
    PRIMARY KEY (source_id, member_key)
);
