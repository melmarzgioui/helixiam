/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import io.helixiam.authorization.domain.realm.RealmKey;
import io.helixiam.authorization.repository.realm.RealmKeyRepository;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.testsupport.LogCapture;
import io.helixiam.testsupport.TestPki;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RealmKeyExpiryMonitorTest {

    private static final TestPki.Ca CA = TestPki.ca("Expiry CA");

    private final RealmKeyRepository repo = mock(RealmKeyRepository.class);
    private final AuditLog audit = mock(AuditLog.class);
    private final RealmKeyExpiryMonitor monitor = new RealmKeyExpiryMonitor(repo, audit, false, 6);

    private static RealmKey key(final String id, final String status, final Instant notAfter) {
        final KeyPair kp = TestPki.rsa(2048);
        final RealmKey k = new RealmKey(id, "acme", "RS256",
                Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()), "secret-private");
        k.setStatus(RealmKey.Status.valueOf(status));
        if (notAfter != null) {
            final X509Certificate c = TestPki.issue(CA.certificate(), CA.keyPair().getPrivate(), "CN=" + id,
                    kp.getPublic(), notAfter.minus(Duration.ofDays(400)), notAfter, KeyUsage.digitalSignature);
            k.setCertificateChainPem(TestPki.pem(c));
        }
        return k;
    }

    @Test
    void warnsOncePerDay_forExpiringAndExpiredActiveOrPendingCertificates() {
        final Instant now = Instant.parse("2026-10-16T08:00:00Z");
        final RealmKey soon = key("soon", "ACTIVE", now.plus(Duration.ofDays(10)));
        final RealmKey gone = key("gone", "PENDING", now.minus(Duration.ofDays(2)));
        final RealmKey fine = key("fine", "ACTIVE", now.plus(Duration.ofDays(200)));
        final RealmKey bare = key("bare", "ACTIVE", null);
        when(repo.findAllByStatusIn(List.of("ACTIVE", "PENDING"))).thenReturn(List.of(soon, gone, fine, bare));
        final LocalDate today = LocalDate.ofInstant(now, ZoneOffset.UTC);
        when(repo.claimExpiryWarning(any(), eq(today))).thenReturn(1);

        final RealmKeyExpiryMonitor.Result result;
        try (LogCapture logs = LogCapture.of(RealmKeyExpiryMonitor.class)) {
            result = monitor.scan(now);
            assertThat(logs.text()).contains("soon").contains("gone").doesNotContain("secret-private")
                    .doesNotContain("BEGIN");
        }
        assertThat(result.expiring()).isEqualTo(1);
        assertThat(result.expired()).isEqualTo(1);
        final ArgumentCaptor<AuditEvent> events = ArgumentCaptor.forClass(AuditEvent.class);
        verify(audit, times(2)).emit(events.capture());
        assertThat(events.getAllValues()).extracting(AuditEvent::type)
                .containsExactlyInAnyOrder("REALM_KEY_CERTIFICATE_EXPIRING", "REALM_KEY_CERTIFICATE_EXPIRED");
        assertThat(events.getAllValues().get(0).detail()).containsKeys("keyId", "algorithm", "fingerprint", "notAfter");
        assertThat(events.getAllValues().toString()).doesNotContain("secret-private");
        assertThat(monitor.last()).isEqualTo(result);

        // Another replica already warned today: counted, not re-announced.
        when(repo.claimExpiryWarning(any(), eq(today))).thenReturn(0);
        final RealmKeyExpiryMonitor.Result again = monitor.scan(now);
        assertThat(again.expiring()).isEqualTo(1);
        verify(audit, times(2)).emit(any());
        verify(repo, never()).claimExpiryWarning(eq("fine"), any());
    }
}
