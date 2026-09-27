-- C3 (email verification): a realm can require a verified email address before any token is issued, and admins can
-- send a user a verification link. Off by default.
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS verify_email boolean NOT NULL DEFAULT false;

-- Single-use verification links. Only the SHA-256 of the token is stored, with the address it was sent to (a link
-- never verifies an address the user changed to afterwards). Consumed atomically (used_at).
CREATE TABLE IF NOT EXISTS email_verification_token (
    token_hash  character varying(64)  NOT NULL PRIMARY KEY,
    realm_id    character varying(255) NOT NULL,
    user_id     character varying(255) NOT NULL,
    email       character varying(255) NOT NULL,
    created_at  timestamp              NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  timestamp              NOT NULL,
    used_at     timestamp              DEFAULT NULL,
    FOREIGN KEY (user_id) REFERENCES user_credentials(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS email_verification_token_expiry_idx ON email_verification_token (expires_at);
CREATE INDEX IF NOT EXISTS email_verification_token_user_idx ON email_verification_token (user_id);
