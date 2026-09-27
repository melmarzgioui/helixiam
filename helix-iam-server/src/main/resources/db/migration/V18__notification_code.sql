-- One-time codes sent by email (sign-up email verification, password reset). The table was missing from both
-- schema paths, so these codes could not be stored: self-registered users could never verify their email (and
-- stayed locked), and password-reset codes were never saved.
CREATE TABLE IF NOT EXISTS notification_code (
    code          character varying(255) NOT NULL PRIMARY KEY,
    identifier    character varying(255) NOT NULL,
    type          character varying(64)  NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS notification_code_identifier_idx ON notification_code (identifier, type);
