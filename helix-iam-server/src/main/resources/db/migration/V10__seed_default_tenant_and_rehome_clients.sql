-- 1.0 item 2: make the Flyway path boot on an empty database and fix clients filed under the wrong realm.
--
-- 1. The platform seed rows used to live only in data.sql (the spring.sql.init path). Under Flyway nothing
--    created them, so ServiceProviderService's initial client (tenant_id '-1234') failed its FK and the
--    application did not start. Seed them here, idempotently.
INSERT INTO tenant (tenant_id, name) VALUES ('-1234', 'HelixIAM')
ON CONFLICT (tenant_id) DO NOTHING;

INSERT INTO user_roles (role_id, name, description, tenant_id) VALUES ('1', 'ROLE_ADMIN', 'Super admin', '-1234')
ON CONFLICT (role_id) DO NOTHING;

-- 2. Before 1.0, clients created through the admin API or realm import got realm_id = 'master' whatever realm
--    they were created in (tenant_id always carried the right realm). Re-home them; the -1234 seed client
--    stays in master.
UPDATE service_provider_oauth SET realm_id = tenant_id
 WHERE realm_id = 'master' AND tenant_id <> 'master' AND tenant_id <> '-1234';
