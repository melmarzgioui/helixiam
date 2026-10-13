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
import io.helixiam.authorization.federation.wallet.transaction.InMemoryWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.JdbcWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.RedisWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransactionStore;
import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.persistence.security.AttributeEncryption;
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
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

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
    public OidcTokenClient oidcTokenClient(final io.helixiam.common.net.OutboundUrlGuard egressGuard) {
        return new HttpOidcTokenClient(egressGuard); // M6: guard the admin-configured token/JWKS URIs
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
    public LdapDirectory ldapDirectory(
            @org.springframework.beans.factory.annotation.Value("${helix.federation.ldap.allowed-hosts:}")
            final String allowedHosts) {
        // LDAP to an internal directory needs the deployment to list it; a realm admin's URL alone cannot reach it
        return new JndiLdapDirectory(new io.helixiam.common.net.LdapEgressGuard(allowedHosts));
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

    // E8.3: load admin-managed providers from the persisted store into the live registry: every realm once at startup,
    // and the written realm after each admin write. On by default (final review F1): the switch used to default off
    // so that the build and deployments without the config exchange never called AMQP at boot, but the store is read
    // in process since RabbitMQ was removed, so that reason is gone. helix.federation.store.enabled=false still turns
    // it off (admin-created connections are then saved but never become loginable).

    @Bean
    @ConditionalOnProperty(prefix = "helix.federation.store", name = "enabled", havingValue = "true", matchIfMissing = true)
    public FederationStoreRefresher federationStoreRefresher(final IdentityProviderConfigSource source,
                                                             final FederationProviderFactory factory,
                                                             final IdentityProviderRegistry registry) {
        return new FederationStoreRefresher(source, factory, registry);
    }

    @Bean
    @ConditionalOnProperty(prefix = "helix.federation.store", name = "enabled", havingValue = "true", matchIfMissing = true)
    public ApplicationRunner federationStoreStartupRefresh(final FederationStoreRefresher refresher) {
        return args -> {
            try {
                final int loaded = refresher.refreshAll();
                LOG.info("Helix federation: startup loaded {} store-backed provider(s) across all realms", loaded);
            } catch (final RuntimeException e) {
                LOG.warn("Helix federation: startup store refresh failed (continuing with config/bean providers): {}",
                        e.getMessage());
            }
        };
    }

    /**
     * Production readiness item 1: polls the per-realm identity-provider config versions so a write or a realm import
     * on another replica reaches this one within {@code helix.federation.store.poll-interval-seconds} (default 10;
     * 0 turns polling off). Plain PostgreSQL, so it works on every deployment.
     */
    @Bean(initMethod = "start", destroyMethod = "close")
    @ConditionalOnProperty(prefix = "helix.federation.store", name = "enabled", havingValue = "true", matchIfMissing = true)
    public FederationStoreVersionPoller federationStoreVersionPoller(
            final FederationStoreRefresher refresher,
            @Value("${helix.federation.store.poll-interval-seconds:10}") final long intervalSeconds) {
        return new FederationStoreVersionPoller(refresher, Duration.ofSeconds(Math.max(0, intervalSeconds)));
    }

    /**
     * EUDI wallet logins: the transaction store (production readiness item 3), shared by every replica.
     * <ul>
     *   <li><b>PostgreSQL</b> ({@link JdbcWalletTransactionStore}) whenever the HTTP session store is {@code queue}
     *       (PostgreSQL), and whenever neither the session nor the token store is Redis;</li>
     *   <li><b>Redis</b> ({@link RedisWalletTransactionStore}, on the session/token store's connection factory) when the
     *       session store is Redis, or the token store is Redis and the session store is not {@code queue};</li>
     *   <li><b>in process memory</b> ({@link InMemoryWalletTransactionStore}, one replica only) for development and
     *       tests, and only when asked for: {@code helix.wallet.transaction-store=memory}.</li>
     * </ul>
     * {@code helix.wallet.transaction-store} ({@code jdbc}, {@code redis} or {@code memory}) overrides the choice. A
     * server that has neither Redis nor a database, and was not asked for memory, refuses to start: it never falls back
     * to a store that silently breaks with a second replica.
     */
    @Configuration(proxyBeanMethods = false)
    public static class WalletTransactionStores {

        static final String PROPERTY = "helix.wallet.transaction-store";

        @Bean // destroy: inferred close() stops the PostgreSQL store's sweep
        @ConditionalOnMissingBean(WalletTransactionStore.class)
        public WalletTransactionStore walletTransactionStore(
                @Value("${" + PROPERTY + ":}") final String explicit,
                @Value("${helix.iam.session-store:}") final String sessionStore,
                @Value("${helix.iam.token-store:}") final String tokenStore,
                @Value("${database.encryption:#{null}}") final String encryptionKey,
                @Value("${helix.wallet.transaction-sweep-seconds:60}") final long sweepSeconds,
                final DeploymentProfile profile,
                final ObjectProvider<RedisConnectionFactory> redis,
                final ObjectProvider<JdbcTemplate> jdbc,
                final ObjectProvider<PlatformTransactionManager> transactions) {
            final String store = choose(explicit, sessionStore, tokenStore);
            switch (store) {
                case "memory" -> {
                    if (!profile.isDev()) {
                        LOG.warn("EUDI wallet logins keep their transactions in process memory ({}=memory): this "
                                + "works with ONE replica only and is meant for development and tests", PROPERTY);
                    }
                    return new InMemoryWalletTransactionStore();
                }
                case "redis" -> {
                    final RedisConnectionFactory factory = redis.getIfAvailable();
                    if (factory == null) {
                        throw new IllegalStateException("The EUDI wallet transaction store is Redis, but no Redis "
                                + "connection is configured (set " + PROPERTY + " or configure Redis)");
                    }
                    return new RedisWalletTransactionStore(factory, new AttributeEncryption(encryptionKey), profile,
                            Clock.systemUTC());
                }
                default -> {
                    final JdbcTemplate template = jdbc.getIfAvailable();
                    final PlatformTransactionManager manager = transactions.getIfAvailable();
                    if (template == null || manager == null) {
                        throw new IllegalStateException("The EUDI wallet transaction store needs the database or "
                                + "Redis; neither is available. Set " + PROPERTY + "=memory for a single-process "
                                + "development or test run.");
                    }
                    final JdbcWalletTransactionStore jdbcStore = new JdbcWalletTransactionStore(template, manager,
                            new AttributeEncryption(encryptionKey), profile, Clock.systemUTC(),
                            Duration.ofSeconds(Math.max(0, sweepSeconds)));
                    jdbcStore.start();
                    return jdbcStore;
                }
            }
        }

        /** Which store: {@code jdbc}, {@code redis} or {@code memory} (see the class javadoc). */
        static String choose(final String explicit, final String sessionStore, final String tokenStore) {
            final String forced = normalise(explicit);
            if (!forced.isEmpty()) {
                if (!List.of("jdbc", "redis", "memory").contains(forced)) {
                    throw new IllegalStateException(PROPERTY + " must be jdbc, redis or memory, not '" + explicit
                            + "'");
                }
                return forced;
            }
            final String session = normalise(sessionStore);
            if ("queue".equals(session)) {
                return "jdbc";
            }
            if ("redis".equals(session) || "redis".equals(normalise(tokenStore))) {
                return "redis";
            }
            return "jdbc";
        }

        private static String normalise(final String value) {
            return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        }
    }

}
