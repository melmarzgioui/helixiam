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
