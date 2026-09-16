/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.risk;

import io.helixiam.authorization.domain.risk.KnownDevice;
import io.helixiam.authorization.domain.risk.KnownLoginIp;
import io.helixiam.authorization.domain.risk.RiskLoginRecord;
import io.helixiam.authorization.domain.risk.RiskSignalRequest;
import io.helixiam.authorization.domain.risk.RiskSignals;
import io.helixiam.authorization.repository.risk.KnownDeviceRepository;
import io.helixiam.authorization.repository.risk.KnownLoginIpRepository;
import io.helixiam.authorization.repository.security.LoginFailureRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.function.Supplier;

/**
 * Helix IAM (adaptive auth): owner of the per-user device/IP login history that backs the
 * risk-based authentication signals. Two operations:
 * <ul>
 *   <li>{@link #evaluate} — resolve the server-side signals (known device, known IP, prior
 *       history, brute-force velocity, new country) for one attempt, for the publisher's
 *       {@code RiskEvaluator} to score. Read-only and side-effect free.</li>
 *   <li>{@link #record} — upsert the remembered-device and login-IP rows after a successful
 *       login so the device/IP become "known" for the next evaluation.</li>
 * </ul>
 *
 * <p>The brute-force velocity is read straight from the {@code login_failure} counter (the same
 * row the account-lockout feature maintains) so the risk signal works even when hard lockout is
 * disabled for the realm. The clock is injectable so the service is unit-testable.
 */
@Service
public class RiskHistoryService {

    private final KnownDeviceRepository deviceRepository;
    private final KnownLoginIpRepository ipRepository;
    private final LoginFailureRepository loginFailureRepository;
    private final Supplier<Instant> clock;

    @org.springframework.beans.factory.annotation.Autowired
    public RiskHistoryService(final KnownDeviceRepository deviceRepository,
                              final KnownLoginIpRepository ipRepository,
                              final LoginFailureRepository loginFailureRepository) {
        this(deviceRepository, ipRepository, loginFailureRepository, Instant::now);
    }

    /** Test seam: inject the clock. */
    public RiskHistoryService(final KnownDeviceRepository deviceRepository,
                              final KnownLoginIpRepository ipRepository,
                              final LoginFailureRepository loginFailureRepository,
                              final Supplier<Instant> clock) {
        this.deviceRepository = deviceRepository;
        this.ipRepository = ipRepository;
        this.loginFailureRepository = loginFailureRepository;
        this.clock = clock;
    }

    /** Resolves the server-side risk signals for one login attempt (read-only). */
    @Transactional(readOnly = true)
    public RiskSignals evaluate(final RiskSignalRequest request) {
        final RiskSignals signals = new RiskSignals();
        final String realmId = request.getRealmId();
        final String userId = request.getUserId();
        if (realmId == null || userId == null) {
            return signals; // nothing resolvable — treated as new device/IP, no history
        }

        final boolean hasDevices = deviceRepository.existsByRealmIdAndUserId(realmId, userId);
        signals.setHasEnrolledDevices(hasDevices);
        final String fingerprint = request.getFingerprint();
        signals.setKnownDevice(fingerprint != null && !fingerprint.isBlank()
                && deviceRepository.findByRealmIdAndUserIdAndFingerprint(realmId, userId, fingerprint).isPresent());

        final List<KnownLoginIp> ipHistory = ipRepository.findAllByRealmIdAndUserId(realmId, userId);
        signals.setHasLoginHistory(!ipHistory.isEmpty());
        final String ip = request.getIp();
        signals.setKnownIp(ip != null && !ip.isBlank()
                && ipHistory.stream().anyMatch(k -> ip.equals(k.getIp())));

        // Best-effort impossible-travel: a country we've never seen for this user. Only meaningful
        // when a geo source supplied a country and the user already has IP history with countries.
        final String country = request.getCountry();
        signals.setNewCountry(country != null && !country.isBlank() && !ipHistory.isEmpty()
                && ipHistory.stream().map(KnownLoginIp::getCountry).noneMatch(country::equals));

        signals.setRecentFailureCount(loginFailureRepository.findByRealmIdAndUserId(realmId, userId)
                .map(io.helixiam.authorization.domain.security.LoginFailure::getFailureCount)
                .orElse(0));
        return signals;
    }

    /** Records a successful login: upserts the device + IP history rows for (realm, user). */
    @Transactional
    public void record(final RiskLoginRecord record) {
        final String realmId = record.getRealmId();
        final String userId = record.getUserId();
        if (realmId == null || userId == null) {
            return;
        }
        final Instant now = clock.get();

        final String fingerprint = record.getFingerprint();
        if (fingerprint != null && !fingerprint.isBlank()) {
            final KnownDevice device = deviceRepository
                    .findByRealmIdAndUserIdAndFingerprint(realmId, userId, fingerprint)
                    .orElseGet(() -> {
                        final KnownDevice d = new KnownDevice(realmId, userId, fingerprint);
                        d.setFirstSeen(now);
                        return d;
                    });
            device.setUserAgent(record.getUserAgent());
            device.setLastSeen(now);
            deviceRepository.save(device);
        }

        final String ip = record.getIp();
        if (ip != null && !ip.isBlank()) {
            final KnownLoginIp known = ipRepository.findByRealmIdAndUserIdAndIp(realmId, userId, ip)
                    .orElseGet(() -> {
                        final KnownLoginIp k = new KnownLoginIp(realmId, userId, ip);
                        k.setFirstSeen(now);
                        return k;
                    });
            if (record.getCountry() != null && !record.getCountry().isBlank()) {
                known.setCountry(record.getCountry());
            }
            known.setLastSeen(now);
            ipRepository.save(known);
        }
    }
}
