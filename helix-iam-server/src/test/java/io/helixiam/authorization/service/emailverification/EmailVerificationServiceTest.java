/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.emailverification;

import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** C3: who must verify their email before tokens are issued. */
class EmailVerificationServiceTest {

    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final EmailVerificationService service = new EmailVerificationService(jdbc,
            mock(UserCredentialsRepository.class), mock(TenantUserRepository.class), m -> true);

    @Test
    void verifyEmailActionParsing() {
        assertThat(EmailVerificationService.hasAction("UPDATE_PASSWORD, verify_email")).isTrue();
        assertThat(EmailVerificationService.hasAction("UPDATE_PASSWORD")).isFalse();
        assertThat(EmailVerificationService.hasAction(null)).isFalse();
        assertThat(EmailVerificationService.withoutAction("VERIFY_EMAIL,UPDATE_PASSWORD")).isEqualTo("UPDATE_PASSWORD");
        assertThat(EmailVerificationService.withoutAction("VERIFY_EMAIL")).isNull();
    }

    @Test
    void pending_whenUnverifiedAndRequiredByTheRealmOrTheAction() {
        realmRequires("strict", true);
        realmRequires("lax", false);
        assertThat(service.pending("strict", user("a@example.com", false, null))).isTrue();
        assertThat(service.pending("strict", user("a@example.com", true, null))).as("verified").isFalse();
        assertThat(service.pending("strict", user(null, false, null))).as("no address").isFalse();
        assertThat(service.pending("lax", user("a@example.com", false, null))).isFalse();
        assertThat(service.pending("lax", user("a@example.com", false, "VERIFY_EMAIL"))).as("explicit action").isTrue();
        assertThat(service.pending("lax", user(null, false, "VERIFY_EMAIL"))).as("explicit action, no address").isTrue();
        assertThat(service.pending("lax", user("a@example.com", true, "VERIFY_EMAIL"))).isFalse();
    }

    @Test
    void consume_rejectsBlankOverlongAndRealmlessTokens() {
        assertThat(service.consume("r", null)).isEmpty();
        assertThat(service.consume("r", " ")).isEmpty();
        assertThat(service.consume("r", "x".repeat(129))).isEmpty();
        assertThat(service.consume(null, "abc")).isEmpty();
    }

    private void realmRequires(final String realm, final boolean required) {
        when(jdbc.queryForList(anyString(), eq(Boolean.class), eq(realm))).thenReturn(List.of(required));
    }

    private static UserCredentials user(final String email, final boolean verified, final String actions) {
        final UserCredentials u = new UserCredentials();
        u.setEmail(email);
        u.setEmailVerified(verified);
        u.setRequiredActions(actions);
        return u;
    }
}
