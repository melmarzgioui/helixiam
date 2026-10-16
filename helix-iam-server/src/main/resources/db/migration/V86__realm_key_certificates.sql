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

-- The same key in two different realms cannot be repaired automatically (deleting either row could break a realm):
-- stop with a message naming the realms, so an operator retires the key in one of them first.
DO $$
DECLARE
    realms text;
BEGIN
    SELECT string_agg(DISTINCT realm_id, ', ' ORDER BY realm_id) INTO realms
      FROM realm_key
     WHERE public_key IN (SELECT public_key FROM realm_key GROUP BY public_key HAVING count(DISTINCT realm_id) > 1);
    IF realms IS NOT NULL THEN
        RAISE EXCEPTION 'V86: the same signing key is stored in more than one realm (%). Delete the duplicate '
            'realm_key rows of all but one of these realms, then restart.', realms;
    END IF;
END $$;

-- rc.11 could store the same key twice in one realm (two concurrent first-use requests): keep, per realm and public
-- key, an ACTIVE row (the newest) or, without one, the newest row, so the unique index below can be built. Idempotent.
DELETE FROM realm_key k
    USING (SELECT key_id,
                  ROW_NUMBER() OVER (PARTITION BY realm_id, public_key
                                     ORDER BY (status = 'ACTIVE') DESC, creation_date DESC NULLS LAST, key_id DESC) AS rn
             FROM realm_key) d
    WHERE k.key_id = d.key_id AND d.rn > 1;
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

-- Round 6: how a federated link was made (JIT, AUTO, SELF, WALLET, ADMIN_CONFIRMED, LEGACY). An administrator signs
-- in through a link only when it is not AUTO: links made after the upgrade by matching a verified e-mail address are
-- refused for administrators. Existing links worked in rc.11 and keep working: they become LEGACY (trusted; every
-- administrator with one is reported at start-up as PRIVILEGED_LEGACY_LINK), except wallet links, which only the
-- account console can make (WALLET). Idempotent: only rows without a value are filled.
-- Round 6: links are realm-scoped (key: realm_id, idp_alias, external_subject); a link signs its user in only in its
-- realm. Backfill: the realm whose identity_provider owns the alias when exactly one does; otherwise (an alias in
-- several realms, or a provider from configuration files) the user's home realm, else their only realm membership,
-- and such a link is AUTO (see below). Rows still without a realm sign no one in and are reported at start-up.
-- Idempotent.
ALTER TABLE federated_link ADD COLUMN IF NOT EXISTS realm_id character varying(255);
UPDATE federated_link f SET realm_id = p.realm_id
  FROM (SELECT alias, min(realm_id) AS realm_id FROM identity_provider GROUP BY alias
        HAVING count(DISTINCT realm_id) = 1) p
 WHERE f.realm_id IS NULL AND p.alias = f.idp_alias;
-- A link placed by the fallbacks below may sit in the wrong realm: it is marked realm_ambiguous and (further down)
-- created_via AUTO, so it never signs in an administrator until a realm admin confirms it; the start-up report lists
-- it as AMBIGUOUS.
ALTER TABLE federated_link ADD COLUMN IF NOT EXISTS realm_ambiguous boolean DEFAULT false NOT NULL;
UPDATE federated_link f SET realm_id = u.realm_id, realm_ambiguous = true
  FROM user_credentials u
 WHERE f.realm_id IS NULL AND u.user_id = f.user_id AND u.realm_id IS NOT NULL;
UPDATE federated_link f SET realm_id = t.tenant_id, realm_ambiguous = true
  FROM (SELECT user_id, min(tenant_id) AS tenant_id FROM tenant_user GROUP BY user_id HAVING count(*) = 1) t
 WHERE f.realm_id IS NULL AND t.user_id = f.user_id;
UPDATE federated_link SET id = realm_id || '|' || idp_alias || '|' || external_subject
 WHERE realm_id IS NOT NULL AND id = idp_alias || '|' || external_subject;
CREATE UNIQUE INDEX IF NOT EXISTS federated_link_realm_subject_uidx
    ON federated_link (realm_id, idp_alias, external_subject);
CREATE INDEX IF NOT EXISTS federated_link_realm_user_idx ON federated_link (realm_id, user_id);
DO $$
DECLARE
    ambiguous integer;
    unplaced integer;
BEGIN
    SELECT count(*) INTO ambiguous FROM federated_link WHERE realm_ambiguous;
    SELECT count(*) INTO unplaced FROM federated_link WHERE realm_id IS NULL;
    IF ambiguous > 0 THEN
        RAISE WARNING 'V86: % federated link(s) name an identity-provider alias that is not in exactly one realm; '
            'they were placed in their user''s home realm and no longer sign in an administrator until a realm admin '
            'confirms them (listed as AMBIGUOUS at start-up).', ambiguous;
    END IF;
    IF unplaced > 0 THEN
        RAISE WARNING 'V86: % federated link(s) could not be placed in a realm and sign no one in.', unplaced;
    END IF;
END $$;
ALTER TABLE federated_link ADD COLUMN IF NOT EXISTS created_via character varying(16);
UPDATE federated_link SET created_via = 'AUTO' WHERE created_via IS NULL AND realm_ambiguous;
UPDATE federated_link f SET created_via = 'WALLET'
 WHERE f.created_via IS NULL
   AND EXISTS (SELECT 1 FROM identity_provider p
                WHERE p.alias = f.idp_alias AND lower(p.protocol) IN ('eudi-wallet', 'openid4vp', 'wallet'));
UPDATE federated_link SET created_via = 'LEGACY' WHERE created_via IS NULL;
CREATE INDEX IF NOT EXISTS federated_link_alias_idx ON federated_link (idp_alias);
