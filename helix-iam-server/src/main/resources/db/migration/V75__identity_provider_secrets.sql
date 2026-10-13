-- Task 4 (security): identity-provider secrets (OIDC clientSecret, eID SP private keys, LDAP bind password, wallet
-- keys; see ProviderSecretKeys) get their own column, encrypted at rest with DB_ENCRYPTION (AttributeEncryption), and
-- are never kept in the plaintext config_json again. The Java migration V75.1 moves existing secrets into it.
ALTER TABLE identity_provider ADD COLUMN IF NOT EXISTS secret_json text;
