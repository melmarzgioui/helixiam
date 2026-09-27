-- Item A8: where a user goes after registering or verifying their email when no sign-in is pending
-- (else they return to the pending authorization request). Must be on one of the realm's registered
-- redirect origins (checked on save and again on use). NULL = the realm's own login page.
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS post_registration_redirect_url character varying(2048);
