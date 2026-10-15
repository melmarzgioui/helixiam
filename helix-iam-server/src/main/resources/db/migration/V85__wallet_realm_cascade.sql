-- ROADMAP ("Realm deletion cleanup"): verifier_signing_key, realm_wallet_pepper and wallet_transaction are
-- realm-scoped but had no cleanup wired to realm_config, so nothing removed them when a realm row was deleted
-- (directly, or by a future realm-delete operation): a realm created again under the same id would silently
-- inherit the previous realm's verifier access key and wallet pepper.
--
-- NOT a foreign key, for any of the three tables. All three are routinely written for a realm id that has no
-- realm_config row yet: WalletAdminController (verifier key import/generate, /admin/realms/{realmId}/wallet) and
-- IdentityProviderAdminController (creating a wallet connection) live under /admin/**, which RealmRoutingFilter
-- passes through WITHOUT the realms.exists() check, and RealmIdInterceptor only validates the realm id's syntax,
-- never that realm_config has a row — so a verifier key is routinely imported, or a wallet connection created,
-- before anyone ever saves that realm's settings (which is what actually creates the realm_config row, via
-- RealmSettingsController's PUT). wallet_transaction is no different in practice: JdbcWalletTransactionStore is
-- exercised directly (its own contract-suite tests, and any caller that isn't the realm-prefixed broker/account
-- HTTP path) against realm ids that were never given a realm_config row either. An ON DELETE CASCADE FK on any of
-- these would also be an insert constraint, breaking a working flow outright the first time it hit such a realm.
--
-- A trigger instead, one for all three tables: it runs only when a realm_config row is actually deleted, never on
-- insert, and (unlike a cleanup step run once by this migration) it keeps working for every future delete,
-- whatever deletes the row. It does not touch rows whose realm_id has no matching realm_config — those are
-- unaffected by this migration, exactly as before it. The cost, accepted here, is that these three tables lose
-- the FK's own referential-integrity guarantee; the trigger only fires on an actual realm_config DELETE.
--
-- The function body is a classic single-quoted string, not a $$-quoted one: schema.sql is also executed by
-- Spring Boot's plain SQL-script initializer (spring.sql.init.mode, the sql-init test path), whose statement
-- splitter is quote-aware but does not understand Postgres dollar-quoting — it would cut this statement in two
-- at the first internal ';' and fail with "Unterminated dollar quote". A single-quoted body has the same
-- internal ';'s, but inside a string literal the splitter correctly leaves them alone.
CREATE OR REPLACE FUNCTION helix_delete_wallet_secrets_for_realm() RETURNS trigger AS '
BEGIN
    DELETE FROM realm_wallet_pepper WHERE realm_id = OLD.realm_id;
    DELETE FROM verifier_signing_key WHERE realm_id = OLD.realm_id;
    DELETE FROM trusted_list_source WHERE realm_id = OLD.realm_id;
    DELETE FROM wallet_transaction WHERE realm_id = OLD.realm_id;
    RETURN OLD;
END;
' LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS realm_config_delete_wallet_secrets ON realm_config;
CREATE TRIGGER realm_config_delete_wallet_secrets
    AFTER DELETE ON realm_config
    FOR EACH ROW
    EXECUTE FUNCTION helix_delete_wallet_secrets_for_realm();

-- The index supports the trigger's DELETE FROM wallet_transaction WHERE realm_id = ... above.
CREATE INDEX IF NOT EXISTS wallet_transaction_realm_idx ON wallet_transaction (realm_id);

-- federated_link (the broker's account-link table, including wallet links) is intentionally left out: it has no
-- realm_id column (keyed by idp_alias + external_subject + user_id, see V1), so neither a trigger nor an FK can
-- key off realm_id for it. It is cleaned up when the linked user is removed, which is unaffected by this change.
