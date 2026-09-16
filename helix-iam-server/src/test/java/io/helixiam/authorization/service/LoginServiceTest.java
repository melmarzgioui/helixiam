/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service;

import io.helixiam.authorization.domain.LoginCredentials;
import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import io.helixiam.authorization.service.security.LoginFailureService;
import io.helixiam.authorization.service.utils.PasswordUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class LoginServiceTest {

    private UserCredentialsRepository repository;
    private PasswordEncoderService passwordEncoderService;
    private TenantUserRepository tenantUserRepository;
    private LoginService service;

    @BeforeEach
    void setUp() {
        repository = mock(UserCredentialsRepository.class);
        passwordEncoderService = new PasswordEncoderService();
        tenantUserRepository = mock(TenantUserRepository.class);
        // No realm memberships by default → lockout is inert in these tests.
        when(tenantUserRepository.findAllByUserId(org.mockito.ArgumentMatchers.any())).thenReturn(List.of());
        service = new LoginService(repository, passwordEncoderService,
                mock(LoginFailureService.class), mock(RealmService.class), tenantUserRepository);
    }

    private LoginCredentials credentials(final String username, final String password) {
        final LoginCredentials lc = mock(LoginCredentials.class);
        when(lc.getUsername()).thenReturn(username);
        when(lc.getPassword()).thenReturn(password);
        return lc;
    }

    @Test
    void legacyLogin_succeeds_andRehashesToArgon2id() {
        final String salt = PasswordUtils.generateSaltValue();
        final UserCredentials user = new UserCredentials();
        user.setUsername("alice");
        user.setPassword(PasswordUtils.preparePassword("pw", salt));
        user.setPasswordSaltValue(salt);
        when(repository.findByUsername("alice")).thenReturn(Optional.of(user));

        final UserCredentials result = service.loginUser(credentials("alice", "pw"));

        assertSame(user, result);
        // migrated in place: now Argon2id, salt dropped, persisted
        assertTrue(passwordEncoderService.isEncoded(user.getPassword()));
        assertNull(user.getPasswordSaltValue());
        verify(repository).save(user);
    }

    @Test
    void argon2Login_succeeds_withoutRehash() {
        final UserCredentials user = new UserCredentials();
        user.setUsername("bob");
        user.setPassword(passwordEncoderService.encode("pw"));
        user.setPasswordSaltValue(null);
        when(repository.findByUsername("bob")).thenReturn(Optional.of(user));

        final UserCredentials result = service.loginUser(credentials("bob", "pw"));

        assertSame(user, result);
        verify(repository, never()).save(user);
    }

    @Test
    void wrongPassword_returnsNull_andDoesNotRehash() {
        final String salt = PasswordUtils.generateSaltValue();
        final UserCredentials user = new UserCredentials();
        user.setUsername("alice");
        user.setPassword(PasswordUtils.preparePassword("pw", salt));
        user.setPasswordSaltValue(salt);
        when(repository.findByUsername("alice")).thenReturn(Optional.of(user));

        assertNull(service.loginUser(credentials("alice", "WRONG")));
        verify(repository, never()).save(user);
    }

    @Test
    void unknownUser_returnsNull() {
        when(repository.findByUsername("ghost")).thenReturn(Optional.empty());
        when(repository.findByEmail("ghost")).thenReturn(Optional.empty());
        assertNull(service.loginUser(credentials("ghost", "pw")));
    }

    @Test
    void login_byEmail_succeeds_whenIdentifierIsNotAUsername() {
        final UserCredentials user = new UserCredentials();
        user.setUsername("carol");
        user.setEmail("carol@example.com");
        user.setPassword(passwordEncoderService.encode("pw"));
        user.setPasswordSaltValue(null);
        // The submitted identifier is the email, so username lookup misses and email lookup hits.
        when(repository.findByUsername("carol@example.com")).thenReturn(Optional.empty());
        when(repository.findByEmail("carol@example.com")).thenReturn(Optional.of(user));

        final UserCredentials result = service.loginUser(credentials("carol@example.com", "pw"));

        assertSame(user, result);
        verify(repository, never()).save(user);
    }

    @Test
    void lockedOut_returnsUserWithLockFlag_withoutCheckingPassword() {
        final io.helixiam.authorization.service.security.LoginFailureService failures =
                mock(io.helixiam.authorization.service.security.LoginFailureService.class);
        final RealmService realmService = mock(RealmService.class);
        final io.helixiam.authorization.domain.realm.RealmConfig realm =
                io.helixiam.authorization.domain.realm.RealmConfig.defaults("gov");
        realm.setLockoutEnabled(true);
        final io.helixiam.authorization.domain.tenant.TenantUser link =
                new io.helixiam.authorization.domain.tenant.TenantUser();
        link.setTenantId("gov");
        when(tenantUserRepository.findAllByUserId(org.mockito.ArgumentMatchers.any())).thenReturn(List.of(link));
        when(realmService.getOrDefault("gov")).thenReturn(realm);
        when(failures.isLockedOut(realm, null)).thenReturn(true);

        final LoginService locking = new LoginService(repository, passwordEncoderService, failures, realmService, tenantUserRepository);

        final UserCredentials user = new UserCredentials();
        user.setUsername("alice");
        user.setPassword(passwordEncoderService.encode("pw"));
        when(repository.findByUsername("alice")).thenReturn(Optional.of(user));

        // Even with the WRONG password, a locked account surfaces the lock (no enumeration), never null.
        final UserCredentials result = locking.loginUser(credentials("alice", "WRONG"));
        assertSame(user, result);
        assertTrue(user.isLocked()); // transient lock flag set → publisher raises LockedException
        verify(repository, never()).save(user);
    }

    @Test
    void login_prefersUsername_overEmail() {
        final UserCredentials byUsername = new UserCredentials();
        byUsername.setUsername("dave");
        byUsername.setPassword(passwordEncoderService.encode("pw"));
        when(repository.findByUsername("dave")).thenReturn(Optional.of(byUsername));

        final UserCredentials result = service.loginUser(credentials("dave", "pw"));

        assertSame(byUsername, result);
        // Username matched, so the email fallback must never be consulted.
        verify(repository, never()).findByEmail("dave");
    }
}
