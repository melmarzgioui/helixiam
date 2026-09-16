package group.mfnr.authorization.federation.ldap;

import group.mfnr.authorization.federation.spi.BrokeredIdentity;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E5.2: the LDAP broker binds the user's credentials against the directory and, on success,
 * maps the directory attributes to a BrokeredIdentity (directory-authoritative, so email is treated
 * as verified). A failed bind yields no identity. The directory itself is behind a seam.
 */
class LdapAuthenticationServiceTest {

    private static final LdapProviderConfig CONFIG = new LdapProviderConfig(
            "corp-ad", "Corp AD", "ldaps://ad.corp:636", "cn=svc,dc=corp", "svc-pw",
            "ou=people,dc=corp", "(uid={0})", "uid", "mail", "givenName", "sn");

    @Test
    void authenticatesAndMapsDirectoryAttributesToABrokeredIdentity() {
        final LdapDirectory directory = (cfg, user, pw) -> Optional.of(Map.of(
                "uid", "ada", "mail", "ada@corp", "givenName", "Ada", "sn", "Lovelace"));
        final LdapAuthenticationService service = new LdapAuthenticationService(directory);

        final Optional<BrokeredIdentity> result = service.authenticate(CONFIG, "ada", "correct-horse");

        assertThat(result).isPresent();
        final BrokeredIdentity identity = result.orElseThrow();
        assertThat(identity.idpAlias()).isEqualTo("corp-ad");
        assertThat(identity.externalSubject()).isEqualTo("ada");
        assertThat(identity.email()).isEqualTo("ada@corp");
        assertThat(identity.emailVerified()).isTrue(); // directory is authoritative for its users
        assertThat(identity.attributes()).containsEntry("firstName", "Ada").containsEntry("lastName", "Lovelace");
    }

    @Test
    void failedBindYieldsNoIdentity() {
        final LdapDirectory directory = (cfg, user, pw) -> Optional.empty();
        final LdapAuthenticationService service = new LdapAuthenticationService(directory);

        assertThat(service.authenticate(CONFIG, "ada", "wrong")).isEmpty();
    }

    @Test
    void fallsBackToUsernameAsSubjectWhenUidAttributeMissing() {
        final LdapDirectory directory = (cfg, user, pw) -> Optional.of(Map.of("mail", "x@corp"));
        final LdapAuthenticationService service = new LdapAuthenticationService(directory);

        assertThat(service.authenticate(CONFIG, "ada", "pw").orElseThrow().externalSubject()).isEqualTo("ada");
    }
}
