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
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM A3: LDAP/AD federation login. The fallback binds the supplied credentials against the
 * realm's LDAP provider, JIT-provisions/links a local user via the broker, and returns it as the
 * UserDetails — making directory federation actually loginable (it was a bean-wired shell before).
 */
class LdapLoginFallbackTest {

    private final IdentityBroker broker = mock(IdentityBroker.class);
    private final FederatedSessionEstablisher establisher = mock(FederatedSessionEstablisher.class);

    private IdentityProviderConfig ldapProvider() {
        return new IdentityProviderConfig("master", "corp-ldap", "ldap", "Corp LDAP", true,
                Map.of("url", "ldaps://dc.corp:636", "bindDn", "cn=svc", "userSearchBase", "ou=people,dc=corp",
                        "userSearchFilter", "(uid={0})", "uidAttribute", "uid", "emailAttribute", "mail"));
    }

    /** A directory that accepts exactly alice/secret and returns her attributes. */
    private LdapDirectory directory() {
        return (config, username, password) ->
                "alice".equals(username) && "secret".equals(password)
                        ? Optional.of(Map.of("uid", "alice", "mail", "alice@corp", "givenName", "Alice"))
                        : Optional.empty();
    }

    private LdapLoginFallback fallback(final IdentityProviderConfigSource source) {
        return new LdapLoginFallback(source, new LdapAuthenticationService(directory()),
                broker, AccountLinkingPolicy.defaults(), establisher);
    }

    @Test
    void bindsLdapProvisionsTheUserAndReturnsItAsTheUserDetails() {
        final UserCredentials provisioned = mock(UserCredentials.class);
        when(broker.broker(any(), any())).thenReturn(BrokerResult.provisioned("user-99"));
        when(establisher.loadUser("user-99")).thenReturn(provisioned);

        final Optional<UserCredentials> result =
                fallback(realm -> List.of(ldapProvider())).authenticate("master", "alice", "secret");

        assertThat(result).containsSame(provisioned);
        verify(broker).broker(any(), any());
        verify(establisher).loadUser("user-99");
    }

    @Test
    void returnsEmptyOnWrongPassword_andNeverBrokers() {
        final Optional<UserCredentials> result =
                fallback(realm -> List.of(ldapProvider())).authenticate("master", "alice", "wrong");

        assertThat(result).isEmpty();
        verify(broker, never()).broker(any(), any());
    }

    @Test
    void returnsEmptyWhenRealmHasNoLdapProvider() {
        final IdentityProviderConfig oidc = new IdentityProviderConfig("master", "corp-oidc", "oidc", "Corp", true, Map.of());
        final Optional<UserCredentials> result =
                fallback(realm -> List.of(oidc)).authenticate("master", "alice", "secret");

        assertThat(result).isEmpty();
        verify(broker, never()).broker(any(), any());
    }

    @Test
    void skipsDisabledLdapProviders() {
        final IdentityProviderConfig disabled = new IdentityProviderConfig("master", "corp-ldap", "ldap", "Corp LDAP", false, Map.of());
        final Optional<UserCredentials> result =
                fallback(realm -> List.of(disabled)).authenticate("master", "alice", "secret");

        assertThat(result).isEmpty();
        verify(broker, never()).broker(any(), any());
    }
}
