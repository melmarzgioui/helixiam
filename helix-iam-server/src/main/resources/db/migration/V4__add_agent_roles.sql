-- Helix IAM Agent (NHI): the agent's OWN least-privilege realm roles (its standing authority, bound 1 of
-- the authorization model). CSV; nullable. Unioned into realm_access.roles at token issuance — never the
-- owner's roles.
ALTER TABLE agent_identity ADD COLUMN IF NOT EXISTS roles character varying(2000);
