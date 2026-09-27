-- 1.0 item 6 (magic link): passwordless sign-in by emailed link, opt-in per realm.
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS magic_link_enabled boolean NOT NULL DEFAULT false;

-- Single-use sign-in links. Only the SHA-256 of the token is stored; a link expires after 15 minutes and is
-- consumed atomically (used_at).
CREATE TABLE IF NOT EXISTS magic_link_token (
    token_hash  character varying(64)  NOT NULL PRIMARY KEY,
    realm_id    character varying(255) NOT NULL,
    user_id     character varying(255) NOT NULL,
    created_at  timestamp              NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  timestamp              NOT NULL,
    used_at     timestamp              DEFAULT NULL,
    FOREIGN KEY (user_id) REFERENCES user_credentials(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS magic_link_token_expiry_idx ON magic_link_token (expires_at);
