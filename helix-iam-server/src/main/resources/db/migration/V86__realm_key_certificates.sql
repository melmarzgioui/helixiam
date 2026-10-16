-- Bring-your-own realm signing keys and certificates (docs/superpowers/specs/2026-10-16-byo-realm-keys-design.md).
--
-- algorithm now holds the JWS algorithm (RS256 / ES256) instead of the JCA key type: every rc.11 row is an RSA key,
-- i.e. RS256. Code still reads a legacy 'RSA' as RS256, because an rc.11 replica can write one during a rolling
-- upgrade (the column default is changed below, but an rc.11 replica's explicit 'RSA' still lands as written).
UPDATE realm_key SET algorithm = 'RS256' WHERE algorithm IS NULL OR algorithm = 'RSA';
ALTER TABLE realm_key ALTER COLUMN algorithm SET DEFAULT 'RS256';

-- The certificate chain (PEM, leaf first) of an imported or CA-signed key; NULL for a key without a certificate
-- (SAML then publishes the deterministic self-signed fallback certificate).
ALTER TABLE realm_key ADD COLUMN IF NOT EXISTS certificate_chain_pem text DEFAULT NULL;
-- The PKCS#10 request generated for a CSR key (public), so the console can download it again.
ALTER TABLE realm_key ADD COLUMN IF NOT EXISTS csr_pem text DEFAULT NULL;
-- GENERATED (the server generated and activated it), IMPORTED (key + chain uploaded) or CSR (generated for a CSR).
ALTER TABLE realm_key ADD COLUMN IF NOT EXISTS source character varying(20) DEFAULT 'GENERATED' NOT NULL;
-- When the key became ACTIVE (NULL for rows from before this release and keys never activated).
ALTER TABLE realm_key ADD COLUMN IF NOT EXISTS activated_date timestamp DEFAULT NULL;
-- The UTC day the certificate-expiry warning was last raised for this key: one warning per key per day, whichever
-- replica claims the day first.
ALTER TABLE realm_key ADD COLUMN IF NOT EXISTS expiry_warned_on date DEFAULT NULL;

-- A key belongs to one realm (its kid is derived from it): the same public key can never be stored twice.
CREATE UNIQUE INDEX IF NOT EXISTS realm_key_public_key_uidx ON realm_key (public_key);

-- Per-realm signing algorithm choices (rows are optional: a realm without one uses RS256 for everything).
-- default_alg: access tokens, logout tokens, delegation and workload-identity tokens, JARM (RS256, PS256 or ES256);
-- ID tokens follow each client's id_token_signed_response_alg instead. saml_alg: RS256 or ES256.
CREATE TABLE IF NOT EXISTS realm_signing_settings (
    realm_id    character varying(255) NOT NULL PRIMARY KEY,
    default_alg character varying(10)  DEFAULT 'RS256' NOT NULL,
    saml_alg    character varying(10)  DEFAULT 'RS256' NOT NULL,
    updated_at  timestamp DEFAULT CURRENT_TIMESTAMP
    );
