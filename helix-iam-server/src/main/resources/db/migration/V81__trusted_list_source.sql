-- EUDI wallet trusted lists (EuTrustedListSource): per realm, the published lists (ETSI TS 119 612 trusted lists or
-- lists of trusted lists, ETSI TS 119 602 LoTE JSON) whose verified service certificates become wallet trust anchors.
-- The first columns are the admin's configuration; the rest is the state of the last refresh, written by the one
-- replica that holds the row's lease (lease_owner / lease_until). services_json is the last GOOD (signature-verified)
-- set of services; it is kept when a later refresh fails, until its NextUpdate plus grace_hours (then fail closed).
-- version is bumped with every write so replicas reload the rows that moved. Times are epoch milliseconds.
CREATE TABLE IF NOT EXISTS trusted_list_source (
    id                  character varying(36)   NOT NULL PRIMARY KEY,
    realm_id            character varying(255)  NOT NULL,
    name                character varying(64)   NOT NULL,
    url                 character varying(2048) NOT NULL,
    format              character varying(32)   NOT NULL,
    signer_certificates text                    NOT NULL,
    service_types       text                    NOT NULL,
    accepted_statuses   text                    NOT NULL,
    territories         text                    NOT NULL,
    grace_hours         integer                 NOT NULL,
    enabled             boolean                 NOT NULL,
    status              character varying(16)   NOT NULL,
    last_attempt_at     bigint,
    last_success_at     bigint,
    list_issued_at      bigint,
    next_update         bigint,
    next_refresh_at     bigint,
    sequence_number     bigint,
    lists_read          integer,
    last_error          character varying(1000),
    services_json       text,
    version             bigint                  NOT NULL,
    lease_owner         character varying(64),
    lease_until         bigint,
    created_at          bigint                  NOT NULL,
    updated_at          bigint                  NOT NULL,
    CONSTRAINT trusted_list_source_realm_name_uq UNIQUE (realm_id, name)
);
