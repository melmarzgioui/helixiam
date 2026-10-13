-- Task 21a (EUDI Wallet / OpenID4VP): the per-realm 256-bit pepper of the wallet subject HMAC
-- (WalletSubjectResolver). Created lazily, once per realm (INSERT ... ON CONFLICT DO NOTHING); pepper is the
-- base64 value encrypted at rest with DB_ENCRYPTION (AttributeEncryption). Never exported.
CREATE TABLE IF NOT EXISTS realm_wallet_pepper (
    realm_id   character varying(255) NOT NULL PRIMARY KEY,
    pepper     text                   NOT NULL,
    created_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL
);
