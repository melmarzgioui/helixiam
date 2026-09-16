package io.helixiam.authorization.federation.ldap;

import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.federation.AccountLinkingPolicy;
import io.helixiam.authorization.federation.BrokerResult;
import io.helixiam.authorization.federation.IdentityBroker;
import io.helixiam.authorization.federation.IdentityProviderConfigSource;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM B10: on-demand LDAP/AD user sync. Enumerates a realm's named LDAP provider (service-account
 * bind, no per-user password) and brokers each directory entry into a local user via the same
 * {@link IdentityBroker} path an LDAP login uses — so synced users are passwordless, linked federated
 * accounts (they authenticate by binding to the directory at login). Idempotent: an already-linked user
 * resolves via its existing link and is not re-provisioned. Pure orchestration over the
 * {@link LdapDirectory} + {@link IdentityProviderConfigSource} seams, so it is unit-testable without a
 * live directory (mirrors the A3 LDAP login).
 */
@Component
public class LdapSyncService {

    private static final Logger LOG = LogManager.getLogger(LdapSyncService.class);

    private final IdentityProviderConfigSource configSource;
    private final LdapDirectory directory;
    private final IdentityBroker broker;
    private final AccountLinkingPolicy linkingPolicy;

    public LdapSyncService(final IdentityProviderConfigSource configSource, final LdapDirectory directory,
                           final IdentityBroker broker, final AccountLinkingPolicy linkingPolicy) {
        this.configSource = configSource;
        this.directory = directory;
        this.broker = broker;
        this.linkingPolicy = linkingPolicy;
    }

    /** Outcome of a sync: how many directory users were resolved to local users, how many failed, and why. */
    public record Result(int synced, int failed, List<String> errors) {
    }

    /** Sync the named enabled LDAP/AD provider in a realm. Unknown/disabled/mismatched alias → an empty result. */
    public Result sync(final String realmId, final String alias) {
        final String realm = realmId == null || realmId.isBlank() ? "master" : realmId;
        int synced = 0;
        int failed = 0;
        final List<String> errors = new ArrayList<>();
        for (final IdentityProviderConfig cfg : configSource.load(realm)) {
            if (!cfg.enabled() || !isLdap(cfg.protocol()) || !alias.equals(cfg.alias())) {
                continue;
            }
            final LdapProviderConfig lc = toLdapConfig(cfg);
            final List<Map<String, String>> users;
            try {
                users = directory.listUsers(lc);
            } catch (final RuntimeException e) {
                errors.add("Directory search failed for " + cfg.alias() + ": " + e.getMessage());
                continue;
            }
            for (final Map<String, String> attrs : users) {
                final String username = attrs.get(lc.uidAttribute());
                if (username == null || username.isBlank()) {
                    failed++;
                    continue;
                }
                try {
                    final BrokerResult result = broker.broker(toIdentity(lc, username, attrs), linkingPolicy);
                    if (result.resolved() && result.userId() != null) {
                        synced++;
                    } else {
                        failed++;
                    }
                } catch (final RuntimeException e) {
                    failed++;
                    errors.add(username + ": " + e.getMessage());
                }
            }
            LOG.info("LDAP sync: provider {} in realm {} → {} synced, {} failed", cfg.alias(), realm, synced, failed);
        }
        return new Result(synced, failed, errors);
    }

    /** Map a directory entry to a brokered identity (directory is authoritative → email is verified). */
    private static BrokeredIdentity toIdentity(final LdapProviderConfig c, final String username,
                                               final Map<String, String> attrs) {
        final String subject = attrs.getOrDefault(c.uidAttribute(), username);
        final String email = attrs.get(c.emailAttribute());
        final Map<String, String> mapped = new HashMap<>();
        putIfPresent(mapped, "firstName", attrs.get(c.firstNameAttribute()));
        putIfPresent(mapped, "lastName", attrs.get(c.lastNameAttribute()));
        mapped.put("username", username);
        return new BrokeredIdentity(c.alias(), subject, email, true, mapped);
    }

    private static void putIfPresent(final Map<String, String> map, final String key, final String value) {
        if (value != null && !value.isBlank()) {
            map.put(key, value);
        }
    }

    private static boolean isLdap(final String protocol) {
        final String p = protocol == null ? "" : protocol.toLowerCase();
        return p.equals("ldap") || p.equals("ad");
    }

    private static LdapProviderConfig toLdapConfig(final IdentityProviderConfig c) {
        final Map<String, String> m = c.config() == null ? Map.of() : c.config();
        return new LdapProviderConfig(c.alias(), c.displayName(), m.get("url"), m.get("bindDn"),
                m.getOrDefault("bindPassword", m.get("bindPw")), m.get("userSearchBase"),
                m.getOrDefault("userSearchFilter", "(uid={0})"), m.getOrDefault("uidAttribute", "uid"),
                m.getOrDefault("emailAttribute", "mail"), m.getOrDefault("firstNameAttribute", "givenName"),
                m.getOrDefault("lastNameAttribute", "sn"));
    }
}
