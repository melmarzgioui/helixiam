-- Helix IAM Agent / NHI (V3) — a first-class non-human identity: an automation, service, or AI agent
-- registered in a realm and owned by an accountable human. (realm_id, name) is the natural key. The
-- agent carries a lifecycle status (ACTIVE | SUSPENDED | EXPIRED | REVOKED) and an auth_method
-- (FEDERATED | SECRET | JWT), and may bind an OIDC client_id for token issuance. Registry record only;
-- no field is secret, so nothing is encrypted at rest. Idempotent (IF NOT EXISTS); applied after V2.
CREATE TABLE IF NOT EXISTS agent_identity (
    id           character varying(255) NOT NULL PRIMARY KEY,
    realm_id     character varying(255) NOT NULL,
    name         character varying(255) NOT NULL,
    display_name character varying(255),
    description  character varying(2000),
    owner        character varying(255) NOT NULL,
    status       character varying(32) DEFAULT 'ACTIVE' NOT NULL,
    auth_method  character varying(32) DEFAULT 'SECRET' NOT NULL,
    client_id    character varying(255),
    scopes       character varying(2000),
    created_at   timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at   timestamp,
    last_used_at timestamp,
    enabled      boolean DEFAULT true NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_identity_realm_idx ON agent_identity (realm_id);
CREATE UNIQUE INDEX IF NOT EXISTS agent_identity_realm_name_idx ON agent_identity (realm_id, name);
