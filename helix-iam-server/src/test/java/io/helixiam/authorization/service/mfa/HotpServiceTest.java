/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.mfa;

import io.helixiam.authorization.domain.mfa.HotpCredentialEntity;
import io.helixiam.authorization.repository.mfa.HotpCredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E3.4: HOTP verification advances the stored counter on success and accepts a code
 * within a small look-ahead window (resync). Uses the RFC 4226 secret and its published codes.
 */
class HotpServiceTest {

    // RFC 4226: secret "12345678901234567890" -> counter 0..3 codes below.
    private static final String SECRET_B64 =
            Base64.getEncoder().encodeToString("12345678901234567890".getBytes(StandardCharsets.US_ASCII));

    private HotpCredentialRepository repository;
    private HotpService service;

    @BeforeEach
    void setUp() {
        repository = mock(HotpCredentialRepository.class);
        service = new HotpService(repository);
        when(repository.save(any(HotpCredentialEntity.class))).thenAnswer(inv -> inv.getArgument(0));
    }

    private void credentialAtCounter(final long counter) {
        when(repository.findByUserId("user-1"))
                .thenReturn(Optional.of(new HotpCredentialEntity("user-1", SECRET_B64, counter)));
    }

    @Test
    void correctCodeAtCurrentCounter_verifies_andAdvancesByOne() {
        credentialAtCounter(0);

        boolean ok = service.verify("user-1", "755224"); // RFC counter 0

        assertThat(ok).isTrue();
        // saved entity advanced to counter 1
        org.mockito.ArgumentCaptor<HotpCredentialEntity> saved =
                org.mockito.ArgumentCaptor.forClass(HotpCredentialEntity.class);
        verify(repository).save(saved.capture());
        assertThat(saved.getValue().getCounter()).isEqualTo(1L);
    }

    @Test
    void codeWithinLookAheadWindow_verifies_andResyncsPastIt() {
        credentialAtCounter(0);

        boolean ok = service.verify("user-1", "969429"); // RFC counter 3 (within window)

        assertThat(ok).isTrue();
        org.mockito.ArgumentCaptor<HotpCredentialEntity> saved =
                org.mockito.ArgumentCaptor.forClass(HotpCredentialEntity.class);
        verify(repository).save(saved.capture());
        assertThat(saved.getValue().getCounter()).isEqualTo(4L); // matched 3 -> next is 4
    }

    @Test
    void wrongCode_fails_andDoesNotAdvance() {
        credentialAtCounter(0);

        assertThat(service.verify("user-1", "000000")).isFalse();
        verify(repository, never()).save(any(HotpCredentialEntity.class));
    }

    @Test
    void noCredential_fails() {
        when(repository.findByUserId("user-1")).thenReturn(Optional.empty());

        assertThat(service.verify("user-1", "755224")).isFalse();
    }
}
