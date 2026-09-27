-- B1: what the realm's account console (/realms/{realm}/account) lets a user do on their own.
-- Removing the authenticator app and downloading one's data were already possible through the account API, so they
-- stay allowed by default; deleting one's own account is new and destructive, so a realm opts in.
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS account_allow_authenticator_removal boolean NOT NULL DEFAULT true;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS account_allow_data_export boolean NOT NULL DEFAULT true;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS account_allow_deletion boolean NOT NULL DEFAULT false;
