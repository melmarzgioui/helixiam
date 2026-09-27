-- Email delivery stage 2: the persisted retry queue and bounced addresses.
--
-- email_retry: one row per email waiting for a retry after a transient failure. The payload is the rendered message
-- (recipients, subject, HTML and text parts, which carry live links and codes) as JSON, encrypted at rest with the
-- database encryption key (DB_ENCRYPTION, AES-GCM) like the other secrets. Times are epoch millis. A worker claims
-- due rows with SELECT ... FOR UPDATE SKIP LOCKED and pushes next_attempt_at forward by a lease, so two replicas never
-- send the same retry; claimed_by is the claim token of that worker. A row is deleted when the email is delivered,
-- fails permanently, expires or is given up.
CREATE TABLE IF NOT EXISTS email_retry (
    message_id       character varying(255) NOT NULL PRIMARY KEY,
    realm_id         character varying(255),
    payload          text                   NOT NULL,
    attempts         integer                NOT NULL,
    created_at       bigint                 NOT NULL,
    next_attempt_at  bigint                 NOT NULL,
    give_up_at       bigint                 NOT NULL,
    expires_at       bigint,
    last_reason      character varying(32),
    claimed_by       character varying(64)
);
CREATE INDEX IF NOT EXISTS email_retry_due_idx ON email_retry (next_attempt_at);

-- A permanently bounced address (epoch millis, and the address that bounced). It shows only while it is still the
-- user's address, and is cleared when the address changes or is verified again.
ALTER TABLE user_credentials ADD COLUMN IF NOT EXISTS email_bounced_at bigint;
ALTER TABLE user_credentials ADD COLUMN IF NOT EXISTS email_bounced_address character varying(255);
