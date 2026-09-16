-- Helix IAM WIF (V2) — Workload Identity Federation credentials. A trust policy binding an external
-- OIDC token's (issuer, subject, audience) to a Helix client identity so a workload (K8s pod, CI job)
-- can exchange an issuer-signed JWT for a Helix access token with NO client secret. No field is secret,
-- so nothing is encrypted at rest. Idempotent (IF NOT EXISTS); applied after V1 baseline.
CREATE TABLE IF NOT EXISTS workload_identity_credential (
    id            character varying(255) NOT NULL PRIMARY KEY,
    realm_id      character varying(255) NOT NULL,
    name          character varying(255) NOT NULL,
    issuer        character varying(2000) NOT NULL,
    jwks_uri      character varying(2000),
    subject       character varying(2000) NOT NULL,
    audience      character varying(2000) NOT NULL,
    client_id     character varying(255) NOT NULL,
    scopes        character varying(2000),
    enabled       boolean DEFAULT true NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS workload_identity_credential_realm_idx ON workload_identity_credential (realm_id);
CREATE INDEX IF NOT EXISTS workload_identity_credential_resolve_idx ON workload_identity_credential (realm_id, issuer, enabled);
