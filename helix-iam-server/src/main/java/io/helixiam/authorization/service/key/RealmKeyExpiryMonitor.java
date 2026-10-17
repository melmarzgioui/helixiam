/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import io.helixiam.authorization.domain.realm.RealmKey;
import io.helixiam.authorization.domain.realm.RealmKeyView;
import io.helixiam.authorization.repository.realm.RealmKeyRepository;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Certificate expiry of realm signing keys (BYO keys D33–D35). Scans ACTIVE and PENDING keys that have a certificate
 * one minute after start-up and every {@code helix.keys.expiry-check.interval-hours} (default 6). A leaf that expires
 * within 30 days, or has expired, raises one audit event per key per UTC day ({@code REALM_KEY_CERTIFICATE_EXPIRING}
 * / {@code REALM_KEY_CERTIFICATE_EXPIRED}) and a WARN log; the day is claimed in the database, so with several
 * replicas only one warns. An expired ACTIVE certificate does not stop signing (D34). Never logs key material.
 */
@Component
public class RealmKeyExpiryMonitor implements SmartLifecycle {

    private static final Logger LOG = LogManager.getLogger(RealmKeyExpiryMonitor.class);
    public static final String EXPIRING = "REALM_KEY_CERTIFICATE_EXPIRING";
    public static final String EXPIRED = "REALM_KEY_CERTIFICATE_EXPIRED";

    private final RealmKeyRepository repository;
    private final AuditLog audit;
    private final boolean enabled;
    private final long intervalHours;
    private volatile ScheduledExecutorService scheduler;
    private volatile Result last = new Result(0, 0, null);

    /** Counts from the last scan ({@code scannedAt} null before the first). */
    public record Result(int expiring, int expired, Instant scannedAt) {
    }

    @Autowired
    public RealmKeyExpiryMonitor(final RealmKeyRepository repository, final AuditLog audit,
                                 @Value("${helix.keys.expiry-check.enabled:true}") final boolean enabled,
                                 @Value("${helix.keys.expiry-check.interval-hours:6}") final long intervalHours) {
        this.repository = repository;
        this.audit = audit;
        this.enabled = enabled;
        this.intervalHours = Math.max(1, intervalHours);
    }

    /** The last scan's counts (the health indicator's details). */
    public Result last() {
        return last;
    }

    /** One scan at {@code now}. */
    public Result scan(final Instant now) {
        int expiring = 0;
        int expired = 0;
        final LocalDate today = LocalDate.ofInstant(now, ZoneOffset.UTC);
        for (final RealmKey key : repository.findAllByStatusIn(List.of("ACTIVE", "PENDING"))) {
            if (key.getCertificateChainPem() == null || key.getCertificateChainPem().isBlank()) {
                continue;
            }
            final X509Certificate leaf;
            try {
                leaf = RealmKeyMaterial.parseChain(key.getCertificateChainPem()).get(0);
            } catch (final RuntimeException e) {
                LOG.warn("Realm signing key has an unreadable certificate realm={} keyId={}",
                        LogSafe.sanitize(key.getRealmId()), LogSafe.sanitize(key.getKeyId()));
                continue;
            }
            final Instant notAfter = leaf.getNotAfter().toInstant();
            final String state = RealmKeyView.expiry(notAfter, now);
            if ("OK".equals(state)) {
                continue;
            }
            final boolean isExpired = "EXPIRED".equals(state);
            if (isExpired) {
                expired++;
            } else {
                expiring++;
            }
            if (repository.claimExpiryWarning(key.getKeyId(), today) == 1) {
                announce(key, leaf, notAfter, isExpired, now);
            }
        }
        final Result result = new Result(expiring, expired, now);
        last = result;
        return result;
    }

    private void announce(final RealmKey key, final X509Certificate leaf, final Instant notAfter,
                          final boolean isExpired, final Instant now) {
        final long days = Duration.between(now, notAfter).toDays();
        if (isExpired) {
            LOG.warn("Realm signing certificate EXPIRED realm={} keyId={} status={} notAfter={}: the key still signs "
                            + "tokens, but SAML SPs that check certificate validity will reject it — attach a renewed "
                            + "certificate or activate a new key", LogSafe.sanitize(key.getRealmId()),
                    LogSafe.sanitize(key.getKeyId()), key.getStatus(), notAfter);
        } else {
            LOG.warn("Realm signing certificate expires in {} days realm={} keyId={} status={} notAfter={}", days,
                    LogSafe.sanitize(key.getRealmId()), LogSafe.sanitize(key.getKeyId()), key.getStatus(), notAfter);
        }
        final Map<String, String> detail = new LinkedHashMap<>();
        detail.put("keyId", key.getKeyId());
        detail.put("algorithm", key.getJwsAlgorithm());
        detail.put("status", key.getStatus());
        detail.put("fingerprint", RealmKeyMaterial.fingerprint(leaf));
        detail.put("notAfter", notAfter.toString());
        detail.put("daysLeft", String.valueOf(days));
        audit.emit(AuditEvent.admin(AuditContext.nowIso(), isExpired ? EXPIRED : EXPIRING, key.getRealmId(), "system",
                null, "realm-key", key.getKeyId(), isExpired ? "FAILURE" : "SUCCESS", detail));
    }

    // ------------------------------------------------------------------------------------------------ lifecycle

    @Override
    public void start() {
        if (!enabled || scheduler != null) {
            return;
        }
        final ScheduledExecutorService s = Executors.newSingleThreadScheduledExecutor(r -> {
            final Thread t = new Thread(r, "realm-key-expiry");
            t.setDaemon(true);
            return t;
        });
        s.scheduleWithFixedDelay(() -> {
            try {
                scan(Instant.now());
            } catch (final RuntimeException e) {
                LOG.warn("Realm signing certificate expiry scan failed: {}", e.getClass().getSimpleName());
            }
        }, 60, TimeUnit.HOURS.toSeconds(intervalHours), TimeUnit.SECONDS);
        scheduler = s;
    }

    @Override
    public void stop() {
        final ScheduledExecutorService s = scheduler;
        scheduler = null;
        if (s != null) {
            s.shutdownNow();
        }
    }

    @Override
    public boolean isRunning() {
        return scheduler != null;
    }
}
