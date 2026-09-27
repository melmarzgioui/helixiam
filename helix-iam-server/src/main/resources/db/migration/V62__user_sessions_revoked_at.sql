-- B1: "sign out other sessions". Browser sessions of the user that signed in before this moment (epoch millis) are
-- ended on their next request, whichever store holds them; the session that asked is exempt. NULL = never.
ALTER TABLE user_credentials ADD COLUMN IF NOT EXISTS sessions_revoked_at bigint;
