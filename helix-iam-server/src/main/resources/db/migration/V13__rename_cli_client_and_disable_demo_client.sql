-- 1.0 item 8: remove the last product names inherited from KubeDNA.
--
-- 1. The built-in CLI public client seeded into every realm was called "kubedna-cli" ("KubeDNA CLI"). It is now
--    "helix-cli" ("HelixIAM CLI"). Rename it in place (keeping its id, so existing grants stay valid), unless a
--    helix-cli already exists in that realm, in which case the old one is soft-deleted.
UPDATE service_provider_oauth AS o
   SET client_id = 'helix-cli', name = 'HelixIAM CLI',
       description = 'Built-in public client for command-line tools (PKCE + device code).'
 WHERE o.client_id = 'kubedna-cli'
   AND NOT EXISTS (SELECT 1 FROM service_provider_oauth n WHERE n.client_id = 'helix-cli' AND n.realm_id = o.realm_id);
UPDATE service_provider_oauth SET deleted = true WHERE client_id = 'kubedna-cli';

-- 2. Earlier builds seeded a demo confidential client "oidc-client" (secret "secret") with redirect URIs on
--    KubeDNA and Postman hosts into every install. Disable it; it is no longer seeded.
UPDATE service_provider_oauth SET deleted = true
 WHERE client_id = 'oidc-client' AND tenant_id = '-1234' AND redirect_uris LIKE '%kubedna%';
