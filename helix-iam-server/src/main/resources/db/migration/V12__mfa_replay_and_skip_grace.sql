-- 1.0 item 6: TOTP replay protection and the per-realm enrolment "skip" grace period.
-- mfa_last_step: the last accepted TOTP time step (unix time / 30 s); a code for the same or an earlier step is refused.
ALTER TABLE user_credentials ADD COLUMN IF NOT EXISTS mfa_last_step bigint;
-- mfa_skip_grace_days: days after account creation during which enrolment may be skipped. 0 = never (default).
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS mfa_skip_grace_days integer NOT NULL DEFAULT 0;
