/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * {@code realmSigningKeys} health (BYO keys D35): always UP — certificate expiry never takes the server out of
 * rotation — with the last expiry scan's counts as details ({@code expiringCertificates}, {@code expiredCertificates}).
 * Part of the readiness group so operators see it there; it reads cached counts and cannot fail.
 */
@Component("realmSigningKeys")
public class RealmSigningKeysHealthIndicator implements HealthIndicator {

    private final RealmKeyExpiryMonitor monitor;

    public RealmSigningKeysHealthIndicator(final RealmKeyExpiryMonitor monitor) {
        this.monitor = monitor;
    }

    @Override
    public Health health() {
        final RealmKeyExpiryMonitor.Result r = monitor.last();
        final Health.Builder b = Health.up()
                .withDetail("expiringCertificates", r.expiring())
                .withDetail("expiredCertificates", r.expired());
        if (r.scannedAt() != null) {
            b.withDetail("lastScan", r.scannedAt().toString());
        }
        if (r.expired() > 0 || r.expiring() > 0) {
            b.withDetail("warning", "Realm signing certificates expire within 30 days or have expired; see the "
                    + "Realm keys console page and the REALM_KEY_CERTIFICATE_* audit events");
        }
        return b.build();
    }
}
