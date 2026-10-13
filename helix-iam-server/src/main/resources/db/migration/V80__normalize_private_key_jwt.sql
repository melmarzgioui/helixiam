-- DCR stored token_endpoint_auth_method as RFC 7591 spells it ('private_key_jwt'); the token endpoint reads
-- 'PRIVATE_KEY_JWT', so those clients fell back to client_secret_basic. Store the spelling the token endpoint reads.
-- A private_key_jwt client without a jwks_url cannot authenticate with a key either way; ClientAuthMethodAudit logs
-- them at startup.
UPDATE service_provider_oauth
   SET token_endpoint_auth_method = 'PRIVATE_KEY_JWT'
 WHERE lower(token_endpoint_auth_method) = 'private_key_jwt'
   AND token_endpoint_auth_method <> 'PRIVATE_KEY_JWT';
