-- Usernames and email addresses are unique per realm (two firms can each have a "joe"), and a user signs in only in
-- their own realm. Every user gets a home realm (user_credentials.realm_id):
--   * from their realm link (tenant_user), preferring master if they have several;
--   * users with a password but no realm link (self-registered before 1.0, which recorded no realm) -> master;
--   * link-less users without a password (federated JIT users from before 1.0) keep a NULL realm; they sign in
--     through their identity provider link, not with a password.
ALTER TABLE user_credentials ADD COLUMN IF NOT EXISTS realm_id character varying(255);

UPDATE user_credentials u SET realm_id = COALESCE(
        (SELECT tu.tenant_id FROM tenant_user tu WHERE tu.user_id = u.user_id AND tu.tenant_id = 'master' LIMIT 1),
        (SELECT min(tu.tenant_id) FROM tenant_user tu WHERE tu.user_id = u.user_id AND tu.tenant_id <> '-1234'),
        CASE WHEN u.password IS NOT NULL THEN 'master' END)
 WHERE u.realm_id IS NULL;

-- The users moved to master above also get the realm link the admin API and roles rely on.
INSERT INTO tenant_user (tenant_user_id, tenant_id, user_id)
SELECT gen_random_uuid()::text, 'master', u.user_id FROM user_credentials u
 WHERE u.realm_id = 'master'
   AND NOT EXISTS (SELECT 1 FROM tenant_user tu WHERE tu.user_id = u.user_id AND tu.tenant_id = 'master')
   AND EXISTS (SELECT 1 FROM tenant t WHERE t.tenant_id = 'master');

ALTER TABLE user_credentials DROP CONSTRAINT IF EXISTS user_credentials_username_key;
DROP INDEX IF EXISTS ux_user_credentials_email;
CREATE UNIQUE INDEX IF NOT EXISTS ux_user_credentials_realm_username ON user_credentials (realm_id, username);
CREATE UNIQUE INDEX IF NOT EXISTS ux_user_credentials_realm_email ON user_credentials (realm_id, email) WHERE email IS NOT NULL;
