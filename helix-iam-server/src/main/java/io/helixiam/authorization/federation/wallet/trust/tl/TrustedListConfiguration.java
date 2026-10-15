/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.startup.DeploymentProfile;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

import javax.net.ssl.SSLContext;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;

/**
 * Wires the EUDI wallet trusted lists ({@code helix.wallet.trusted-lists.*}):
 * <ul>
 *   <li>{@code refresh-interval-minutes} (default 360): longest time between refreshes of a healthy source (a list's
 *       NextUpdate comes sooner when earlier);</li>
 *   <li>{@code retry-interval-minutes} (default 15): wait after a failed refresh;</li>
 *   <li>{@code check-interval-seconds} (default 60, 0 = off): how often each replica looks for due sources;</li>
 *   <li>{@code poll-interval-seconds} (default 10, 0 = off): how often each replica reloads sources that moved;</li>
 *   <li>{@code max-bytes} (default 16 MB): the largest list fetched;</li>
 *   <li>{@code signer-expiry-grace-days} (default 0): how long after its expiry an admin-pinned signer of a top-level
 *       list may still verify a list issued while it was valid (ETSI TS 119 615 PRO-4.1.4-07/08);</li>
 *   <li>{@code member-signer-expiry-grace-days} (default 180): the same for a member list's signer named by the
 *       verified list of lists (PRO-4.2.4-09);</li>
 *   <li>{@code max-validity-months} (default 6): a list's NextUpdate is capped at its issue time plus this.</li>
 * </ul>
 * Lists are fetched with the JDK's default trust store, through the {@link OutboundUrlGuard} bean.
 */
@Configuration(proxyBeanMethods = false)
public class TrustedListConfiguration {

    @Bean
    public TrustedListRepository trustedListRepository(final JdbcTemplate jdbc,
                                                       final PlatformTransactionManager transactions) {
        return new TrustedListRepository(jdbc, transactions);
    }

    @Bean
    public TrustedListService trustedListService(final TrustedListRepository repository, final OutboundUrlGuard guard,
            final AuditLog auditLog, final DeploymentProfile profile,
            final io.helixiam.authorization.service.federation.IdentityProviderConfigService providers,
            @Value("${database.encryption:#{null}}") final String encryptionKey,
            @Value("${helix.wallet.trusted-lists.refresh-interval-minutes:360}") final long refreshMinutes,
            @Value("${helix.wallet.trusted-lists.retry-interval-minutes:15}") final long retryMinutes,
            @Value("${helix.wallet.trusted-lists.max-bytes:" + SecureXml.DEFAULT_MAX_BYTES + "}") final long maxBytes,
            @Value("${helix.wallet.trusted-lists.signer-expiry-grace-days:0}") final long signerGraceDays,
            @Value("${helix.wallet.trusted-lists.member-signer-expiry-grace-days:180}") final long memberGraceDays,
            @Value("${helix.wallet.trusted-lists.max-validity-months:6}") final int maxValidityMonths)
            throws NoSuchAlgorithmException {
        final TrustedListLoader loader = new TrustedListLoader(
                new PinnedTrustedListFetcher(guard, SSLContext.getDefault(), maxBytes), Clock.systemUTC(), maxBytes,
                new TrustedListLoader.Settings(Duration.ofDays(Math.max(0, signerGraceDays)),
                        Duration.ofDays(Math.max(0, memberGraceDays)),
                        java.time.Period.ofMonths(Math.max(1, maxValidityMonths))));
        final TrustedListService service = new TrustedListService(repository, loader, auditSink(auditLog),
                Clock.systemUTC(),
                new TrustedListService.Settings(Duration.ofMinutes(Math.max(5, refreshMinutes)),
                        Duration.ofMinutes(Math.max(1, retryMinutes)), Duration.ofMinutes(2)),
                TrustedListIntegrity.fromSecret(encryptionKey), profile.isDev());
        // providers reference a source by name: the service asks which ones before a rename
        service.setReferences((realm, name) -> providers.list(realm).stream()
                .filter(p -> io.helixiam.authorization.federation.FederationProviderFactory.isWallet(p.protocol()))
                .filter(p -> namesSource(p.config() == null ? null : p.config().get("trustedLists.sources"), name))
                .map(io.helixiam.authorization.domain.federation.IdentityProviderConfig::alias).sorted().toList());
        return service;
    }

    static boolean namesSource(final String json, final String name) {
        if (json == null || json.isBlank()) {
            return false;
        }
        try {
            for (final com.fasterxml.jackson.databind.JsonNode n : new com.fasterxml.jackson.databind.ObjectMapper()
                    .readTree(json)) {
                if (name.equals(n.asText())) {
                    return true;
                }
            }
        } catch (final Exception e) {
            return false;
        }
        return false;
    }

    @Bean(initMethod = "start", destroyMethod = "close")
    public TrustedListScheduler trustedListScheduler(final TrustedListService service,
            @Value("${helix.wallet.trusted-lists.poll-interval-seconds:10}") final long pollSeconds,
            @Value("${helix.wallet.trusted-lists.check-interval-seconds:60}") final long checkSeconds) {
        return new TrustedListScheduler(service, Duration.ofSeconds(pollSeconds), Duration.ofSeconds(checkSeconds));
    }

    /** Refresh events are ADMIN-category audit records of resource type {@code trusted-list}, actor {@code system}. */
    static TrustedListService.AuditSink auditSink(final AuditLog auditLog) {
        return (realm, type, sourceId, outcome, detail) -> auditLog.emit(AuditEvent.admin(AuditContext.nowIso(), type,
                realm, "system", null, "trusted-list", sourceId, outcome, Map.copyOf(detail)));
    }
}
