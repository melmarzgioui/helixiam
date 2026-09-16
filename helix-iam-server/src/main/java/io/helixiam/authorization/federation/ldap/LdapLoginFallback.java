/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.ldap;

import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.federation.AccountLinkingPolicy;
import io.helixiam.authorization.federation.BrokerResult;
import io.helixiam.authorization.federation.FederatedSessionEstablisher;
import io.helixiam.authorization.federation.IdentityBroker;
import io.helixiam.authorization.federation.IdentityProviderConfigSource;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;

/**
 * Helix IAM A3: makes LDAP / Active Directory user federation actually loginable. The password login
 * ({@code service.AuthenticationProvider}) calls this when the local credential store has no matching
 * user (or rejects the password): for each enabled LDAP/AD provider in the realm it binds the supplied
 * credentials against the directory ({@link LdapAuthenticationService}); on a successful bind it
 * just-in-time provisions / links a local user via the {@link IdentityBroker} and returns that user as
 * the {@link UserCredentials} (UserDetails) so the rest of the login proceeds exactly as for a local user.
 *
 * <p>Before A3 the LDAP classes were bean-wired but had no runtime entry point — directory federation was
 * a shell. This is the missing path. It is strictly additive: a realm with no LDAP provider, or a bind
 * that fails, returns empty and the login fails as before. All errors are contained so a flaky directory
 * can never throw out of the auth path.
 */
@Component
public class LdapLoginFallback {

    private static final Logger LOG = LogManager.getLogger(LdapLoginFallback.class);

    private final IdentityProviderConfigSource configSource;
    private final LdapAuthenticationService ldap;
    private final IdentityBroker broker;
    private final AccountLinkingPolicy linkingPolicy;
    private final FederatedSessionEstablisher sessionEstablisher;

    public LdapLoginFallback(final IdentityProviderConfigSource configSource, final LdapAuthenticationService ldap,
                             final IdentityBroker broker, final AccountLinkingPolicy linkingPolicy,
                             final FederatedSessionEstablisher sessionEstablisher) {
        this.configSource = configSource;
        this.ldap = ldap;
        this.broker = broker;
        this.linkingPolicy = linkingPolicy;
        this.sessionEstablisher = sessionEstablisher;
    }

    /** Bind against the realm's LDAP/AD provider(s); on success return the brokered local user. */
    public Optional<UserCredentials> authenticate(final String realmId, final String username, final String password) {
        final String realm = (realmId == null || realmId.isBlank()) ? "master" : realmId;
        for (final IdentityProviderConfig cfg : configSource.load(realm)) {
            if (!cfg.enabled() || !isLdap(cfg.protocol())) {
                continue;
            }
            try {
                final Optional<BrokeredIdentity> identity = ldap.authenticate(toLdapConfig(cfg), username, password);
                if (identity.isEmpty()) {
                    continue; // unknown user / wrong password at this directory — try the next provider
                }
                final BrokerResult result = broker.broker(identity.get(), linkingPolicy);
                if (result.resolved() && result.userId() != null) {
                    final UserCredentials user = sessionEstablisher.loadUser(result.userId());
                    LOG.info("LDAP login: '{}' authenticated via provider {} → local user {}",
                            username, cfg.alias(), result.userId());
                    return Optional.of(user);
                }
            } catch (final RuntimeException e) {
                LOG.warn("LDAP login attempt via provider {} failed (continuing): {}", cfg.alias(), e.getMessage());
            }
        }
        return Optional.empty();
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
