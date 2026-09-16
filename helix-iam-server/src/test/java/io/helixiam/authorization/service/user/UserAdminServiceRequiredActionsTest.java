/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.user;

import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.tenant.TenantRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import io.helixiam.authorization.service.PasswordEncoderService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Helix IAM B1: per-user required actions (set / get / clear-one). */
class UserAdminServiceRequiredActionsTest {

    private UserCredentialsRepository users;
    private UserAdminService service;

    @BeforeEach
    void setUp() {
        users = mock(UserCredentialsRepository.class);
        service = new UserAdminService(mock(TenantUserRepository.class), mock(TenantRepository.class), users, mock(PasswordEncoderService.class));
        when(users.save(any(UserCredentials.class))).thenAnswer(i -> i.getArgument(0));
    }

    private UserCredentials user(final String actions) {
        final UserCredentials u = new UserCredentials();
        u.setRequiredActions(actions);
        return u;
    }

    @Test
    void setRequiredActions_storesCsv_andTrue() {
        final UserCredentials u = user(null);
        when(users.findByUserId("u1")).thenReturn(Optional.of(u));
        assertThat(service.setRequiredActions("u1", "UPDATE_PASSWORD,VERIFY_EMAIL")).isTrue();
        assertThat(u.getRequiredActions()).isEqualTo("UPDATE_PASSWORD,VERIFY_EMAIL");
    }

    @Test
    void setRequiredActions_blankClearsToNull_missingUserFalse() {
        final UserCredentials u = user("UPDATE_PASSWORD");
        when(users.findByUserId("u1")).thenReturn(Optional.of(u));
        assertThat(service.setRequiredActions("u1", "  ")).isTrue();
        assertThat(u.getRequiredActions()).isNull();
        when(users.findByUserId("missing")).thenReturn(Optional.empty());
        assertThat(service.setRequiredActions("missing", "X")).isFalse();
    }

    @Test
    void getRequiredActions_returnsStored() {
        when(users.findByUserId("u1")).thenReturn(Optional.of(user("UPDATE_PASSWORD")));
        assertThat(service.getRequiredActions("u1")).isEqualTo("UPDATE_PASSWORD");
    }

    @Test
    void clearRequiredAction_removesOne_caseInsensitive_andNullsWhenEmpty() {
        final UserCredentials u = user("UPDATE_PASSWORD,VERIFY_EMAIL");
        when(users.findByUserId("u1")).thenReturn(Optional.of(u));
        assertThat(service.clearRequiredAction("u1", "update_password")).isEqualTo("VERIFY_EMAIL");
        assertThat(u.getRequiredActions()).isEqualTo("VERIFY_EMAIL");
        assertThat(service.clearRequiredAction("u1", "VERIFY_EMAIL")).isEmpty();
        assertThat(u.getRequiredActions()).isNull();
    }
}
