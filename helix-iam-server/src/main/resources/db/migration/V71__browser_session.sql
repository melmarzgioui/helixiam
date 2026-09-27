-- rc.6 item 7b: the account console lists every browser a user is signed in with, whichever HTTP-session store holds
-- the sessions (Redis cannot list a user's sessions). One row per browser sign-in (its OIDC sid): the HTTP session
-- that currently carries it, the device it signed in from and when (epoch millis). The session store stays the
-- truth: a row whose HTTP session is gone is ignored and removed.
CREATE TABLE IF NOT EXISTS browser_session (
    sid              character varying(64)  NOT NULL PRIMARY KEY,
    user_id          character varying(255) NOT NULL,
    http_session_id  character varying(255) NOT NULL,
    browser          character varying(32),
    os               character varying(32),
    signed_in_at     bigint                 NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user_credentials(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS browser_session_user_idx ON browser_session (user_id);
