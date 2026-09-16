package group.mfnr.authorization.federation.ldap;

import group.mfnr.authorization.amqp.federation.IdentityProviderConfig;
import group.mfnr.authorization.federation.AccountLinkingPolicy;
import group.mfnr.authorization.federation.FederatedIdentityStore;
import group.mfnr.authorization.federation.IdentityBroker;
import group.mfnr.authorization.federation.IdentityProviderConfigSource;
import group.mfnr.authorization.federation.DefaultAttributeMapper;
import group.mfnr.authorization.federation.spi.BrokeredIdentity;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM B10: LDAP sync. {@link LdapSyncService} enumerates a directory (service-account bind, no
 * per-user password) and brokers each entry into a local user — the same JIT/link path as an LDAP login,
 * so synced users are passwordless federated accounts. Seam-tested against a stub directory + an
 * in-memory federated store (no live LDAP), exactly like the A3 LDAP login.
 */
class LdapSyncServiceTest {

    /** In-memory federated store standing in for the subscriber. */
    private static final class FakeStore implements FederatedIdentityStore {
        final Map<String, String> links = new HashMap<>();
        final Map<String, String> usersByEmail = new HashMap<>();
        int provisioned = 0;

        @Override public Optional<String> findLinkedUser(final String a, final String s) {
            return Optional.ofNullable(links.get(a + "|" + s));
        }
        @Override public Optional<String> findUserByEmail(final String email) {
            return Optional.ofNullable(usersByEmail.get(email));
        }
        @Override public void link(final String a, final String s, final String userId) {
            links.put(a + "|" + s, userId);
        }
        @Override public String provisionUser(final BrokeredIdentity id, final Map<String, String> attrs) {
            final String userId = "ldap-user-" + (++provisioned);
            if (id.email() != null) {
                usersByEmail.put(id.email(), userId);
            }
            return userId;
        }
    }

    private final FakeStore store = new FakeStore();
    private final IdentityBroker broker = new IdentityBroker(store, new DefaultAttributeMapper());

    private IdentityProviderConfigSource configSource(final IdentityProviderConfig... cfgs) {
        return realmId -> List.of(cfgs);
    }

    private IdentityProviderConfig ldapConfig(final String alias, final boolean enabled) {
        final Map<String, String> cfg = new HashMap<>();
        cfg.put("url", "ldap://dir.example:389");
        cfg.put("userSearchBase", "ou=people,dc=example,dc=com");
        cfg.put("uidAttribute", "uid");
        cfg.put("emailAttribute", "mail");
        return new IdentityProviderConfig("master", alias, "ldap", "Corp Directory", enabled, cfg);
    }

    private LdapDirectory directoryReturning(final List<Map<String, String>> users) {
        return new LdapDirectory() {
            @Override public Optional<Map<String, String>> authenticate(final LdapProviderConfig c, final String u, final String p) {
                return Optional.empty();
            }
            @Override public List<Map<String, String>> listUsers(final LdapProviderConfig c) {
                return users;
            }
        };
    }

    @Test
    void syncsEveryDirectoryUserAsAPasswordlessFederatedAccount() {
        final LdapDirectory directory = directoryReturning(List.of(
                Map.of("uid", "ada", "mail", "ada@corp.example", "givenName", "Ada", "sn", "Lovelace"),
                Map.of("uid", "grace", "mail", "grace@corp.example")));
        final LdapSyncService service = new LdapSyncService(
                configSource(ldapConfig("corp", true)), directory, broker, AccountLinkingPolicy.defaults());

        final LdapSyncService.Result result = service.sync("master", "corp");

        assertThat(result.synced()).isEqualTo(2);
        assertThat(result.failed()).isZero();
        assertThat(store.provisioned).isEqualTo(2);
        assertThat(store.findLinkedUser("corp", "ada")).isPresent();
    }

    @Test
    void isIdempotent_existingLinkedUsersAreNotReprovisioned() {
        store.link("corp", "ada", "existing-7");
        final LdapDirectory directory = directoryReturning(List.of(Map.of("uid", "ada", "mail", "ada@corp.example")));
        final LdapSyncService service = new LdapSyncService(
                configSource(ldapConfig("corp", true)), directory, broker, AccountLinkingPolicy.defaults());

        final LdapSyncService.Result result = service.sync("master", "corp");

        assertThat(result.synced()).isEqualTo(1);
        assertThat(store.provisioned).isZero(); // returning link → no new user
    }

    @Test
    void onlySyncsTheNamedEnabledLdapProvider() {
        final LdapDirectory directory = directoryReturning(List.of(Map.of("uid", "ada", "mail", "ada@x")));
        // alias mismatch → nothing synced
        final LdapSyncService mismatch = new LdapSyncService(
                configSource(ldapConfig("corp", true)), directory, broker, AccountLinkingPolicy.defaults());
        assertThat(mismatch.sync("master", "other").synced()).isZero();

        // disabled provider → nothing synced
        final LdapSyncService disabled = new LdapSyncService(
                configSource(ldapConfig("corp", false)), directory, broker, AccountLinkingPolicy.defaults());
        assertThat(disabled.sync("master", "corp").synced()).isZero();
    }

    @Test
    void skipsEntriesWithNoUid() {
        final LdapDirectory directory = directoryReturning(List.of(
                Map.of("mail", "noid@corp.example"), Map.of("uid", "ada", "mail", "ada@corp.example")));
        final LdapSyncService service = new LdapSyncService(
                configSource(ldapConfig("corp", true)), directory, broker, AccountLinkingPolicy.defaults());

        final LdapSyncService.Result result = service.sync("master", "corp");

        assertThat(result.synced()).isEqualTo(1);
        assertThat(result.failed()).isEqualTo(1);
    }
}
