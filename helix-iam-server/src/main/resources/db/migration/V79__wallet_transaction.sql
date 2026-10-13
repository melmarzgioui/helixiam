-- Production readiness (EUDI wallet, item 3): the PostgreSQL wallet transaction store (JdbcWalletTransactionStore),
-- so a multi-replica deployment without Redis (the queue session store) needs no sticky sessions. One row per
-- transaction. Bearer secrets are looked up by their SHA-256 (base64url) only, exactly like the Redis store: the two
-- request ids, the response id and the response code (the code is kept ONLY as its hash). The request ids, the
-- response id, the ephemeral private JWK and the verified identity are encrypted at rest (DB_ENCRYPTION,
-- AttributeEncryption). Times are epoch milliseconds of the application clock; expired rows read as absent and a
-- periodic sweep deletes them.
CREATE TABLE IF NOT EXISTS wallet_transaction (
    transaction_id            character varying(64)  NOT NULL PRIMARY KEY,
    same_device_request_hash  character varying(64)  NOT NULL UNIQUE,
    cross_device_request_hash character varying(64)  NOT NULL UNIQUE,
    response_hash             character varying(64)  NOT NULL UNIQUE,
    code_hash                 character varying(64)  UNIQUE,
    same_device_request       text                   NOT NULL,
    cross_device_request      text                   NOT NULL,
    response                  text                   NOT NULL,
    realm_id                  character varying(255) NOT NULL,
    provider_alias            character varying(255),
    helix_state               text,
    browser_binding           character varying(255),
    nonce                     text,
    encryption_jwk            text,
    dcql_query                text,
    flow                      character varying(16),
    status                    character varying(24)  NOT NULL,
    verified_identity         text,
    failure_code              character varying(64),
    purpose                   character varying(8)   NOT NULL,
    initiating_user_id        character varying(255),
    created_at                bigint,
    expires_at                bigint                 NOT NULL
);
CREATE INDEX IF NOT EXISTS wallet_transaction_expires_idx ON wallet_transaction (expires_at);
