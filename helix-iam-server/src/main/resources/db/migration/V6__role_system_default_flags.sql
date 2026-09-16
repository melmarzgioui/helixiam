-- Helix IAM: curated default roles per realm. Two flags on user_roles so the admin console can protect
-- the seeded roles (admin / user / auditor) from deletion and mark the one role auto-assigned to every
-- new user. Both default false so existing rows are unaffected; the DefaultRolesBootstrapService sets them.
ALTER TABLE user_roles ADD COLUMN IF NOT EXISTS system_role  boolean NOT NULL DEFAULT false;
ALTER TABLE user_roles ADD COLUMN IF NOT EXISTS default_role boolean NOT NULL DEFAULT false;
