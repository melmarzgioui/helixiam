/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.federation.ldap.JndiLdapDirectory;
import io.helixiam.authorization.federation.ldap.LdapDirectory;
import io.helixiam.authorization.federation.oidc.HttpOidcTokenClient;
import io.helixiam.authorization.federation.oidc.OidcTokenClient;
import io.helixiam.authorization.federation.saml.InMemorySamlAssertionReplayCache;
import io.helixiam.authorization.federation.saml.SamlAssertionReplayCache;
import io.helixiam.authorization.federation.spi.AttributeMapper;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

/**
 * Helix IAM E5.3/E5.4: wires the identity-federation runtime. The {@link IdentityBroker} is pure
 * orchestration over the AMQP-backed {@link FederatedIdentityStore} and the discovered
 * {@link AttributeMapper}; the {@link AccountLinkingPolicy} governs verified-email linking + JIT
 * provisioning (safe defaults, overridable per deployment).
 *
 * <p>The {@link IdentityProviderRegistry} is assembled from auto-discovered {@code IdentityProvider}
 * {@code @Component} beans plus the providers {@link FederationProviderFactory} builds from
 * {@code helix.federation.*} config (E5.4) — so onboarding an external IdP is a bean or a config entry.
 */
@Configuration
@EnableConfigurationProperties(FederationProviderProperties.class)
public class FederationConfig {

    private static final Logger LOG = LogManager.getLogger(FederationConfig.class);

    @Bean
    public IdentityBroker identityBroker(final FederatedIdentityStore store, final AttributeMapper attributeMapper) {
        return new IdentityBroker(store, attributeMapper);
    }

    @Bean
    @ConditionalOnMissingBean(AccountLinkingPolicy.class)
    public AccountLinkingPolicy accountLinkingPolicy() {
        return AccountLinkingPolicy.defaults();
    }

    // Replaceable defaults for the federation collaborators. Declared as @Bean @ConditionalOnMissingBean
    // here (NOT @ConditionalOnMissingBean on the @Component classes, where the condition is evaluated
    // unreliably during component scanning) so a deployment can override any of them with its own bean.

    @Bean
    @ConditionalOnMissingBean(OidcTokenClient.class)
    public OidcTokenClient oidcTokenClient() {
        return new HttpOidcTokenClient();
    }

    @Bean
    @ConditionalOnMissingBean(AttributeMapper.class)
    public AttributeMapper attributeMapper() {
        return new DefaultAttributeMapper();
    }

    @Bean
    @ConditionalOnMissingBean(SamlAssertionReplayCache.class)
    public SamlAssertionReplayCache samlAssertionReplayCache() {
        return new InMemorySamlAssertionReplayCache();
    }

    @Bean
    @ConditionalOnMissingBean(LdapDirectory.class)
    public LdapDirectory ldapDirectory() {
        return new JndiLdapDirectory();
    }

    /** A3: the LDAP/AD bind broker — consulted by the password login when a realm has an LDAP provider. */
    @Bean
    public io.helixiam.authorization.federation.ldap.LdapAuthenticationService ldapAuthenticationService(final LdapDirectory directory) {
        return new io.helixiam.authorization.federation.ldap.LdapAuthenticationService(directory);
    }

    @Bean
    public IdentityProviderRegistry identityProviderRegistry(final ObjectProvider<IdentityProvider> discovered,
                                                             final FederationProviderFactory factory,
                                                             final FederationProviderProperties properties) {
        final List<IdentityProvider> providers = new ArrayList<>();
        discovered.orderedStream().forEach(providers::add);
        final int discoveredCount = providers.size();
        final List<IdentityProvider> configured = factory.build(properties);
        providers.addAll(configured);
        LOG.info("Helix federation: registering {} identity provider(s) ({} discovered + {} configured)",
                providers.size(), discoveredCount, configured.size());
        return new IdentityProviderRegistry(providers);
    }

    // E8.3: load admin-managed providers from the persisted store into the live registry, on demand
    // (and once at startup). Gated by helix.federation.store.enabled (default off) so a deployment
    // without the E8.2 config exchange — or the build/tests — never call AMQP at boot.

    @Bean
    @ConditionalOnProperty(prefix = "helix.federation.store", name = "enabled", havingValue = "true")
    public FederationStoreRefresher federationStoreRefresher(final IdentityProviderConfigSource source,
                                                             final FederationProviderFactory factory,
                                                             final IdentityProviderRegistry registry) {
        return new FederationStoreRefresher(source, factory, registry);
    }

    @Bean
    @ConditionalOnProperty(prefix = "helix.federation.store", name = "enabled", havingValue = "true")
    public ApplicationRunner federationStoreStartupRefresh(
            final FederationStoreRefresher refresher,
            @Value("${helix.federation.store.realm:master}") final String realmId) {
        return args -> {
            try {
                final int loaded = refresher.refresh(realmId);
                LOG.info("Helix federation: startup loaded {} store-backed provider(s) for realm {}", loaded, realmId);
            } catch (final RuntimeException e) {
                LOG.warn("Helix federation: startup store refresh failed (continuing with config/bean providers): {}",
                        e.getMessage());
            }
        };
    }
}
