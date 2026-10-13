-- Production readiness (EUDI wallet, item 1): one row per realm whose identity-provider configs were ever written,
-- bumped in the same transaction as every write (admin API, console, realm import). Each replica polls this table
-- (helix.federation.store.poll-interval-seconds) and reloads the realms whose version moved, so a write reaches every
-- replica without a restart; publication is version-ordered, so an older set never replaces a newer one.
CREATE TABLE IF NOT EXISTS idp_config_version (
    realm_id   character varying(255) NOT NULL PRIMARY KEY,
    version    bigint                 NOT NULL,
    updated_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL
);
