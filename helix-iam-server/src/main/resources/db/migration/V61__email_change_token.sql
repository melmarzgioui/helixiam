-- B1: single-use links that confirm a changed email address. Only the SHA-256 of the link token is stored; the link is
-- bound to the address it was sent to, so it confirms nothing once the user changed the address again.
CREATE TABLE IF NOT EXISTS email_change_token (
    token_hash  character varying(64)  NOT NULL PRIMARY KEY,
    realm_id    character varying(255) NOT NULL,
    user_id     character varying(255) NOT NULL,
    email       character varying(255) NOT NULL,
    created_at  timestamp              NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  timestamp              NOT NULL,
    used_at     timestamp              DEFAULT NULL,
    FOREIGN KEY (user_id) REFERENCES user_credentials(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS email_change_token_user_idx ON email_change_token (user_id);
