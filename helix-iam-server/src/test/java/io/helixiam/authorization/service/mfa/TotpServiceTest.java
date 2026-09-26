/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.mfa;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;
import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** 1.0 item 6: TOTP window (±1 step), replay protection and enrolment confirmation. */
class TotpServiceTest {

    private static final String SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    private static final long NOW = 1_790_000_000_000L; // fixed clock
    private static final long STEP = NOW / 1000 / 30;

    private static String code(final long step) throws Exception {
        return TimeBasedOneTimePasswordUtil.generateNumberString(SECRET, step * 30_000L, 30, 6);
    }

    @Test
    void acceptsTheCurrentStepAndOneEitherSide_only() throws Exception {
        assertThat(TotpService.matchingStep(SECRET, code(STEP), Long.MIN_VALUE, NOW)).hasValue(STEP);
        assertThat(TotpService.matchingStep(SECRET, code(STEP - 1), Long.MIN_VALUE, NOW)).hasValue(STEP - 1);
        assertThat(TotpService.matchingStep(SECRET, code(STEP + 1), Long.MIN_VALUE, NOW)).hasValue(STEP + 1);
        assertThat(TotpService.matchingStep(SECRET, code(STEP - 2), Long.MIN_VALUE, NOW)).isEmpty();
        assertThat(TotpService.matchingStep(SECRET, code(STEP + 2), Long.MIN_VALUE, NOW)).isEmpty();
    }

    @Test
    void refusesTheSameOrAnEarlierStepThanTheLastAccepted() throws Exception {
        assertThat(TotpService.matchingStep(SECRET, code(STEP), STEP, NOW)).isEmpty();
        assertThat(TotpService.matchingStep(SECRET, code(STEP - 1), STEP, NOW)).isEmpty();
        assertThat(TotpService.matchingStep(SECRET, code(STEP + 1), STEP, NOW)).hasValue(STEP + 1);
    }

    @Test
    void rejectsMalformedInputAndMissingSecret() throws Exception {
        assertThat(TotpService.matchingStep(SECRET, "skip", Long.MIN_VALUE, NOW)).isEmpty();
        assertThat(TotpService.matchingStep(SECRET, "12345", Long.MIN_VALUE, NOW)).isEmpty();
        assertThat(TotpService.matchingStep(SECRET, null, Long.MIN_VALUE, NOW)).isEmpty();
        assertThat(TotpService.matchingStep(null, code(STEP), Long.MIN_VALUE, NOW)).isEmpty();
    }

    @Test
    void verify_recordsTheStepAtomically_andAConcurrentReplayLoses() throws Exception {
        final UserCredentialsRepository repo = mock(UserCredentialsRepository.class);
        final UserCredentials user = new UserCredentials();
        user.setMfaEnabled(true);
        user.setMfaSecret(SECRET);
        user.setMfaLastStep(STEP - 5);
        when(repo.findByUserId("u")).thenReturn(Optional.of(user));
        when(repo.advanceMfaStep("u", STEP)).thenReturn(1, 0);
        final TotpService totp = new TotpService(repo, () -> NOW);

        assertThat(totp.verify("u", code(STEP))).isTrue();
        assertThat(totp.verify("u", code(STEP))).as("the conditional update refused it").isFalse();
    }

    @Test
    void verify_refusesUsersWithoutAConfirmedSecret() throws Exception {
        final UserCredentialsRepository repo = mock(UserCredentialsRepository.class);
        final UserCredentials user = new UserCredentials();
        user.setMfaEnabled(false);
        when(repo.findByUserId("u")).thenReturn(Optional.of(user));
        assertThat(new TotpService(repo, () -> NOW).verify("u", code(STEP))).isFalse();
        verify(repo, never()).advanceMfaStep(eq("u"), anyLong());
    }

    @Test
    void confirmEnrolment_storesSecretOnlyForAValidCode() throws Exception {
        final UserCredentialsRepository repo = mock(UserCredentialsRepository.class);
        final UserCredentials user = new UserCredentials();
        when(repo.findByUserId("u")).thenReturn(Optional.of(user));
        final TotpService totp = new TotpService(repo, () -> NOW);

        assertThat(totp.confirmEnrolment("u", SECRET, "000000".equals(code(STEP)) ? "111111" : "000000")).isFalse();
        assertThat(user.isMfaEnabled()).isFalse();
        assertThat(totp.confirmEnrolment("u", SECRET, code(STEP))).isTrue();
        assertThat(user.isMfaEnabled()).isTrue();
        assertThat(user.getMfaSecret()).isEqualTo(SECRET);
        assertThat(user.getMfaLastStep()).isEqualTo(STEP);
    }

    @Test
    void otpauthUri_usesTheRealmNameAsIssuerAndLabel() {
        assertThat(TotpService.otpauthUri("Monthfold Books", "joe@harbor-pine.example", SECRET))
                .isEqualTo("otpauth://totp/Monthfold%20Books:joe%40harbor-pine.example?secret=" + SECRET
                        + "&issuer=Monthfold%20Books&algorithm=SHA1&digits=6&period=30");
    }
}
