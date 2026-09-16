-- Helix IAM multi-tenant fix: an OAuth client id is unique WITHIN a realm, not globally.
--
-- The V1 baseline carried a legacy single-realm `UNIQUE (client_id)` on service_provider_oauth. Every
-- other client-scoped table (client_role, client_protocol_mapper, client_service_account_role, …) already
-- keys on `(realm_id, client_id)`. The global constraint blocks the intended multi-tenant behaviour —
-- e.g. the built-in `kubedna-cli` public client seeded per realm, or any customer reusing a client id
-- across two realms (normal in Keycloak). Runtime resolution is already realm-scoped
-- (ServiceProviderRepository.findByClientIdAndRealmIdAndDeleted), so scoping the constraint is safe.
--
-- Drop the global unique and replace it with the composite `(client_id, realm_id)`.

ALTER TABLE service_provider_oauth DROP CONSTRAINT IF EXISTS service_provider_oauth_client_id_key;

-- Some pre-baseline databases may have named the constraint differently; drop by any known alias too.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'service_provider_oauth'::regclass
          AND contype = 'u'
          AND pg_get_constraintdef(oid) = 'UNIQUE (client_id)'
    ) THEN
        EXECUTE (
            SELECT 'ALTER TABLE service_provider_oauth DROP CONSTRAINT ' || quote_ident(conname)
            FROM pg_constraint
            WHERE conrelid = 'service_provider_oauth'::regclass
              AND contype = 'u'
              AND pg_get_constraintdef(oid) = 'UNIQUE (client_id)'
            LIMIT 1
        );
    END IF;
END $$;

ALTER TABLE service_provider_oauth
    ADD CONSTRAINT service_provider_oauth_client_id_realm_id_key UNIQUE (client_id, realm_id);
