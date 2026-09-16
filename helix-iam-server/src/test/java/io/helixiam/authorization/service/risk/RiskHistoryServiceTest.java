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
import io.helixiam.authorization.domain.security.LoginFailure;
import io.helixiam.authorization.repository.risk.KnownDeviceRepository;
import io.helixiam.authorization.repository.risk.KnownLoginIpRepository;
import io.helixiam.authorization.repository.security.LoginFailureRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Helix IAM (adaptive auth): resolving signals (known vs new device/IP, velocity, new country) + recording. */
class RiskHistoryServiceTest {

    private KnownDeviceRepository deviceRepo;
    private KnownLoginIpRepository ipRepo;
    private LoginFailureRepository failureRepo;
    private AtomicReference<Instant> now;
    private RiskHistoryService service;

    @BeforeEach
    void setUp() {
        deviceRepo = mock(KnownDeviceRepository.class);
        ipRepo = mock(KnownLoginIpRepository.class);
        failureRepo = mock(LoginFailureRepository.class);
        now = new AtomicReference<>(Instant.parse("2026-01-01T00:00:00Z"));
        service = new RiskHistoryService(deviceRepo, ipRepo, failureRepo, now::get);
    }

    private RiskSignalRequest request(final String fingerprint, final String ip, final String country) {
        RiskSignalRequest r = new RiskSignalRequest();
        r.setRealmId("gov");
        r.setUserId("u1");
        r.setFingerprint(fingerprint);
        r.setIp(ip);
        r.setCountry(country);
        return r;
    }

    @Test
    void knownDeviceAndKnownIp_areReported() {
        when(deviceRepo.existsByRealmIdAndUserId("gov", "u1")).thenReturn(true);
        when(deviceRepo.findByRealmIdAndUserIdAndFingerprint("gov", "u1", "fp"))
                .thenReturn(Optional.of(new KnownDevice("gov", "u1", "fp")));
        KnownLoginIp ip = new KnownLoginIp("gov", "u1", "1.2.3.4");
        ip.setCountry("NL");
        when(ipRepo.findAllByRealmIdAndUserId("gov", "u1")).thenReturn(List.of(ip));
        when(failureRepo.findByRealmIdAndUserId("gov", "u1")).thenReturn(Optional.empty());

        RiskSignals s = service.evaluate(request("fp", "1.2.3.4", "NL"));

        assertThat(s.isHasEnrolledDevices()).isTrue();
        assertThat(s.isKnownDevice()).isTrue();
        assertThat(s.isHasLoginHistory()).isTrue();
        assertThat(s.isKnownIp()).isTrue();
        assertThat(s.isNewCountry()).isFalse();
        assertThat(s.getRecentFailureCount()).isZero();
    }

    @Test
    void newDeviceAndNewIp_andNewCountry_areReported() {
        when(deviceRepo.existsByRealmIdAndUserId("gov", "u1")).thenReturn(true);
        when(deviceRepo.findByRealmIdAndUserIdAndFingerprint("gov", "u1", "fp-new"))
                .thenReturn(Optional.empty());
        KnownLoginIp ip = new KnownLoginIp("gov", "u1", "9.9.9.9");
        ip.setCountry("NL");
        when(ipRepo.findAllByRealmIdAndUserId("gov", "u1")).thenReturn(List.of(ip));
        LoginFailure f = new LoginFailure("gov", "u1");
        f.setFailureCount(2);
        when(failureRepo.findByRealmIdAndUserId("gov", "u1")).thenReturn(Optional.of(f));

        RiskSignals s = service.evaluate(request("fp-new", "1.2.3.4", "DE"));

        assertThat(s.isKnownDevice()).isFalse();
        assertThat(s.isKnownIp()).isFalse();
        assertThat(s.isNewCountry()).isTrue();          // DE never seen, only NL on record
        assertThat(s.getRecentFailureCount()).isEqualTo(2);
    }

    @Test
    void noHistory_meansNoKnownDeviceOrIp_butSignalsSuppressableUpstream() {
        when(deviceRepo.existsByRealmIdAndUserId("gov", "u1")).thenReturn(false);
        when(deviceRepo.findByRealmIdAndUserIdAndFingerprint(any(), any(), any())).thenReturn(Optional.empty());
        when(ipRepo.findAllByRealmIdAndUserId("gov", "u1")).thenReturn(List.of());
        when(failureRepo.findByRealmIdAndUserId("gov", "u1")).thenReturn(Optional.empty());

        RiskSignals s = service.evaluate(request("fp", "1.2.3.4", "NL"));

        assertThat(s.isHasEnrolledDevices()).isFalse();
        assertThat(s.isHasLoginHistory()).isFalse();
        assertThat(s.isNewCountry()).isFalse(); // no prior IP history → not "new country"
    }

    @Test
    void record_insertsNewDeviceAndIp() {
        when(deviceRepo.findByRealmIdAndUserIdAndFingerprint("gov", "u1", "fp")).thenReturn(Optional.empty());
        when(ipRepo.findByRealmIdAndUserIdAndIp("gov", "u1", "1.2.3.4")).thenReturn(Optional.empty());

        RiskLoginRecord record = new RiskLoginRecord();
        record.setRealmId("gov");
        record.setUserId("u1");
        record.setFingerprint("fp");
        record.setIp("1.2.3.4");
        record.setCountry("NL");
        record.setUserAgent("agent");
        service.record(record);

        ArgumentCaptor<KnownDevice> deviceCap = ArgumentCaptor.forClass(KnownDevice.class);
        verify(deviceRepo).save(deviceCap.capture());
        assertThat(deviceCap.getValue().getFingerprint()).isEqualTo("fp");
        assertThat(deviceCap.getValue().getFirstSeen()).isEqualTo(now.get());
        assertThat(deviceCap.getValue().getLastSeen()).isEqualTo(now.get());

        ArgumentCaptor<KnownLoginIp> ipCap = ArgumentCaptor.forClass(KnownLoginIp.class);
        verify(ipRepo).save(ipCap.capture());
        assertThat(ipCap.getValue().getIp()).isEqualTo("1.2.3.4");
        assertThat(ipCap.getValue().getCountry()).isEqualTo("NL");
    }

    @Test
    void record_refreshesLastSeenOnExistingDevice() {
        KnownDevice existing = new KnownDevice("gov", "u1", "fp");
        existing.setFirstSeen(Instant.parse("2025-01-01T00:00:00Z"));
        when(deviceRepo.findByRealmIdAndUserIdAndFingerprint("gov", "u1", "fp")).thenReturn(Optional.of(existing));
        when(ipRepo.findByRealmIdAndUserIdAndIp(eq("gov"), eq("u1"), any())).thenReturn(Optional.empty());

        RiskLoginRecord record = new RiskLoginRecord();
        record.setRealmId("gov");
        record.setUserId("u1");
        record.setFingerprint("fp");
        record.setIp("1.2.3.4");
        service.record(record);

        assertThat(existing.getLastSeen()).isEqualTo(now.get());
        assertThat(existing.getFirstSeen()).isEqualTo(Instant.parse("2025-01-01T00:00:00Z")); // unchanged
    }
}
