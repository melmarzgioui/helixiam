-- Helix MCP demo — provisions the client + agent the demo authenticates as, in the `master` realm.
-- Idempotent (WHERE NOT EXISTS). Clones an existing confidential client's SAS settings so we don't have to
-- hand-author the client_settings / token_settings JSON blobs.

-- 1. A confidential client_credentials client the MCP agent uses to obtain tokens.
INSERT INTO service_provider_oauth
  (service_provider_id, client_id, client_secret, client_authentication_methods, authorization_grant_types,
   redirect_uris, scopes, client_settings, token_settings, tenant_id, realm_id, name, public_client, deleted)
SELECT gen_random_uuid(), 'mcp-agent-client', '{noop}s3cr3t-mcp-agent-123', 'client_secret_basic', 'client_credentials',
   redirect_uris, scopes, client_settings, token_settings, tenant_id, realm_id, 'MCP demo agent client', false, false
FROM service_provider_oauth
WHERE client_id = 'helix-example-app' AND realm_id = 'master'
  AND NOT EXISTS (SELECT 1 FROM service_provider_oauth WHERE client_id = 'mcp-agent-client' AND realm_id = 'master');

-- 2. The agent (non-human identity) bound to that client.
INSERT INTO agent_identity
  (id, realm_id, name, display_name, description, owner, status, auth_method, client_id, scopes, roles, created_at, enabled)
SELECT gen_random_uuid(), 'master', 'mcp-demo-agent', 'MCP demo agent', 'calls a Helix-protected MCP server',
   'alice@acme.example', 'ACTIVE', 'SECRET', 'mcp-agent-client', 'openid', 'mcp:tools', now(), true
WHERE NOT EXISTS (SELECT 1 FROM agent_identity WHERE realm_id = 'master' AND name = 'mcp-demo-agent');
