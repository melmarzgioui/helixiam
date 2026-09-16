/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.device;

import io.helixiam.authorization.domain.device.DeviceCredentialEntity;
import io.helixiam.authorization.repository.device.DeviceCredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E4.1: device enrollment verifies platform attestation (via the registry) before storing
 * the device's P-256 public key, and device assertions are verified by ES256 over the exact server
 * challenge. Enrollment+assertion are the parts provable without a real device; attestation content
 * itself is the pluggable verifier's job (here the registry is mocked).
 */
class DeviceCredentialServiceTest {

    private DeviceCredentialRepository repository;
    private AttestationVerifierRegistry attestation;
    private DeviceCredentialService service;
    private KeyPair deviceKey;

    @BeforeEach
    void setUp() throws Exception {
        repository = mock(DeviceCredentialRepository.class);
        attestation = mock(AttestationVerifierRegistry.class);
        service = new DeviceCredentialService(repository, attestation);
        when(repository.save(any(DeviceCredentialEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        deviceKey = kpg.generateKeyPair();
    }

    private byte[] sign(final byte[] message) throws Exception {
        final Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(deviceKey.getPrivate());
        s.update(message);
        return s.sign();
    }

    @Test
    void enroll_storesTheCredential_whenAttestationPasses() {
        when(attestation.verify(anyString(), any(), any(), any())).thenReturn(true);

        final boolean ok = service.enroll("user-1", "device-1", deviceKey.getPublic().getEncoded(),
                "none", new byte[0], "nonce".getBytes(StandardCharsets.UTF_8), true);

        assertThat(ok).isTrue();
        final ArgumentCaptor<DeviceCredentialEntity> saved = ArgumentCaptor.forClass(DeviceCredentialEntity.class);
        verify(repository).save(saved.capture());
        assertThat(saved.getValue().getDeviceId()).isEqualTo("device-1");
        assertThat(saved.getValue().getUserId()).isEqualTo("user-1");
        assertThat(saved.getValue().getPlatform()).isEqualTo("none");
        assertThat(saved.getValue().isBiometric()).isTrue();
        // stored SPKI round-trips
        assertThat(Base64.getDecoder().decode(saved.getValue().getPublicKey()))
                .isEqualTo(deviceKey.getPublic().getEncoded());
    }

    @Test
    void enroll_isRejected_whenAttestationFails() {
        when(attestation.verify(anyString(), any(), any(), any())).thenReturn(false);

        final boolean ok = service.enroll("user-1", "device-1", deviceKey.getPublic().getEncoded(),
                "apple-app-attest", new byte[]{9}, "nonce".getBytes(StandardCharsets.UTF_8), true);

        assertThat(ok).isFalse();
        verify(repository, never()).save(any());
    }

    @Test
    void verifyAssertion_acceptsAGenuineDeviceSignature_andStampsLastUsed() throws Exception {
        final String spkiB64 = Base64.getEncoder().encodeToString(deviceKey.getPublic().getEncoded());
        when(repository.findById("device-1"))
                .thenReturn(Optional.of(new DeviceCredentialEntity("device-1", "user-1", spkiB64, "none", true)));
        final byte[] challenge = "single-use-challenge".getBytes(StandardCharsets.UTF_8);

        final boolean ok = service.verifyAssertion("user-1", "device-1", challenge, sign(challenge));

        assertThat(ok).isTrue();
        final ArgumentCaptor<DeviceCredentialEntity> saved = ArgumentCaptor.forClass(DeviceCredentialEntity.class);
        verify(repository).save(saved.capture());
        assertThat(saved.getValue().getLastUsedDate()).isNotNull();
    }

    @Test
    void verifyAssertion_rejectsAWrongUserForTheDevice() throws Exception {
        final String spkiB64 = Base64.getEncoder().encodeToString(deviceKey.getPublic().getEncoded());
        when(repository.findById("device-1"))
                .thenReturn(Optional.of(new DeviceCredentialEntity("device-1", "user-1", spkiB64, "none", true)));
        final byte[] challenge = "c".getBytes(StandardCharsets.UTF_8);

        assertThat(service.verifyAssertion("attacker", "device-1", challenge, sign(challenge))).isFalse();
        verify(repository, never()).save(any());
    }

    @Test
    void verifyAssertion_rejectsAnUnknownDevice() {
        when(repository.findById("ghost")).thenReturn(Optional.empty());

        assertThat(service.verifyAssertion("user-1", "ghost", new byte[]{1}, new byte[]{2})).isFalse();
    }
}
