package group.mfnr.authorization.federation.ldap;

import group.mfnr.authorization.federation.spi.BrokeredIdentity;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Helix IAM E5.2: the LDAP broker. Binds the user's credentials against the directory (via the
 * {@link LdapDirectory} seam) and, on success, maps the directory attributes to a
 * {@link BrokeredIdentity} that the {@link group.mfnr.authorization.federation.IdentityBroker} turns
 * into a local user (JIT/linking). The directory is authoritative for its users, so the email is
 * treated as verified.
 */
public class LdapAuthenticationService {

    private final LdapDirectory directory;

    public LdapAuthenticationService(final LdapDirectory directory) {
        this.directory = directory;
    }

    public Optional<BrokeredIdentity> authenticate(final LdapProviderConfig config,
                                                   final String username, final String password) {
        return directory.authenticate(config, username, password).map(attrs -> {
            final String subject = attrs.getOrDefault(config.uidAttribute(), username);
            final String email = attrs.get(config.emailAttribute());

            final Map<String, String> mapped = new HashMap<>();
            putIfPresent(mapped, "firstName", attrs.get(config.firstNameAttribute()));
            putIfPresent(mapped, "lastName", attrs.get(config.lastNameAttribute()));
            mapped.put("username", username);

            return new BrokeredIdentity(config.alias(), subject, email, true, mapped);
        });
    }

    private static void putIfPresent(final Map<String, String> map, final String key, final String value) {
        if (value != null && !value.isBlank()) {
            map.put(key, value);
        }
    }
}
