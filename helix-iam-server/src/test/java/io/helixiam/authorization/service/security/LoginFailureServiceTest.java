package io.helixiam.authorization.service.security;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.domain.security.LoginFailure;
import io.helixiam.authorization.repository.security.LoginFailureRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Auth-hardening (feature 1): the account-lockout / brute-force state machine. */
class LoginFailureServiceTest {

    private LoginFailureRepository repository;
    private AtomicReference<Instant> now;
    private LoginFailureService service;

    private RealmConfig realm;

    @BeforeEach
    void setUp() {
        repository = mock(LoginFailureRepository.class);
        now = new AtomicReference<>(Instant.parse("2026-01-01T00:00:00Z"));
        service = new LoginFailureService(repository, now::get);
        realm = RealmConfig.defaults("gov");
        realm.setLockoutEnabled(true);
        realm.setMaxLoginFailures(3);
        realm.setLockoutDurationSeconds(900);
        realm.setFailureResetSeconds(900);
        when(repository.save(any(LoginFailure.class))).thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void lockoutDisabled_isNoOp() {
        realm.setLockoutEnabled(false);
        assertThat(service.recordFailure(realm, "u1")).isFalse();
        assertThat(service.isLockedOut(realm, "u1")).isFalse();
        verify(repository, never()).save(any());
    }

    @Test
    void locksAfterThreshold_withinWindow() {
        final AtomicReference<LoginFailure> stored = new AtomicReference<>();
        when(repository.findByRealmIdAndUserId("gov", "u1")).thenAnswer(inv -> Optional.ofNullable(stored.get()));
        when(repository.save(any(LoginFailure.class))).thenAnswer(inv -> { stored.set(inv.getArgument(0)); return inv.getArgument(0); });

        assertThat(service.recordFailure(realm, "u1")).isFalse(); // 1
        assertThat(service.recordFailure(realm, "u1")).isFalse(); // 2
        assertThat(service.recordFailure(realm, "u1")).isTrue();  // 3 -> locked

        assertThat(service.isLockedOut(realm, "u1")).isTrue();
        assertThat(stored.get().getFailureCount()).isEqualTo(3);
        assertThat(stored.get().getLockedUntil()).isEqualTo(now.get().plusSeconds(900));
    }

    @Test
    void failureAfterWindow_restartsCount() {
        final LoginFailure f = new LoginFailure("gov", "u1");
        f.setFailureCount(2);
        f.setLastFailure(now.get().minusSeconds(901)); // older than the 900s window
        LoginFailureService.applyFailure(f, realm, now.get());
        assertThat(f.getFailureCount()).isEqualTo(1);
        assertThat(f.getLockedUntil()).isNull();
    }

    @Test
    void lockExpires_afterDuration() {
        final LoginFailure f = new LoginFailure("gov", "u1");
        f.setLockedUntil(now.get().plusSeconds(900));
        assertThat(LoginFailureService.isLocked(f, now.get())).isTrue();
        assertThat(LoginFailureService.isLocked(f, now.get().plusSeconds(901))).isFalse();
    }

    @Test
    void permanentLockout_usesInstantMax() {
        realm.setPermanentLockout(true);
        final LoginFailure f = new LoginFailure("gov", "u1");
        f.setFailureCount(2);
        f.setLastFailure(now.get());
        LoginFailureService.applyFailure(f, realm, now.get()); // 3rd -> permanent
        assertThat(f.getLockedUntil()).isEqualTo(Instant.MAX);
        assertThat(LoginFailureService.isLocked(f, now.get().plusSeconds(10_000_000))).isTrue();
    }

    @Test
    void success_clearsCounter() {
        final LoginFailure f = new LoginFailure("gov", "u1");
        when(repository.findByRealmIdAndUserId("gov", "u1")).thenReturn(Optional.of(f));
        service.recordSuccess(realm, "u1");
        verify(repository).delete(f);
    }
}
