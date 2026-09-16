-- Per-realm self-registration switch (Helix IAM: per-realm registration).
-- Defaults TRUE so existing realms keep today's behaviour; the global master flag still applies.
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS registration_enabled boolean DEFAULT true NOT NULL;
