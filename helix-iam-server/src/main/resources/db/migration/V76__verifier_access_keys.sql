-- Task 5 (EUDI Wallet / OpenID4VP): per-realm verifier access-certificate signing keys (software store of
-- RealmSigningKeys). private_key is the PKCS#8 PEM encrypted at rest with DB_ENCRYPTION (AttributeEncryption);
-- certificate_chain_pem is the public X.509 chain, leaf first, without the trust anchor.
CREATE TABLE IF NOT EXISTS verifier_signing_key (
    realm_id              character varying(255) NOT NULL,
    name                  character varying(64)  NOT NULL,
    alg                   character varying(16)  NOT NULL,
    private_key           text                   NOT NULL,
    certificate_chain_pem text                   NOT NULL,
    created_at            timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (realm_id, name)
);
