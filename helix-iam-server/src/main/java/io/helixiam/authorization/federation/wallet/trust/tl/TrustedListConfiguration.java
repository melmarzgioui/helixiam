/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.common.net.OutboundUrlGuard;
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
 *   <li>{@code signer-expiry-grace-days} (default 180): how long after its expiry a signer may still verify a list
 *       issued while it was valid;</li>
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
            final AuditLog auditLog,
            @Value("${helix.wallet.trusted-lists.refresh-interval-minutes:360}") final long refreshMinutes,
            @Value("${helix.wallet.trusted-lists.retry-interval-minutes:15}") final long retryMinutes,
            @Value("${helix.wallet.trusted-lists.max-bytes:" + SecureXml.DEFAULT_MAX_BYTES + "}") final long maxBytes,
            @Value("${helix.wallet.trusted-lists.signer-expiry-grace-days:180}") final long signerGraceDays,
            @Value("${helix.wallet.trusted-lists.max-validity-months:6}") final int maxValidityMonths)
            throws NoSuchAlgorithmException {
        final TrustedListLoader loader = new TrustedListLoader(
                new PinnedTrustedListFetcher(guard, SSLContext.getDefault(), maxBytes), Clock.systemUTC(), maxBytes,
                new TrustedListLoader.Settings(Duration.ofDays(Math.max(0, signerGraceDays)),
                        java.time.Period.ofMonths(Math.max(1, maxValidityMonths))));
        return new TrustedListService(repository, loader, auditSink(auditLog), Clock.systemUTC(),
                new TrustedListService.Settings(Duration.ofMinutes(Math.max(5, refreshMinutes)),
                        Duration.ofMinutes(Math.max(1, retryMinutes)), Duration.ofMinutes(2)));
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
