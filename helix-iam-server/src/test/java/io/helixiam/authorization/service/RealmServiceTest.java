package io.helixiam.authorization.service;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.repository.realm.RealmConfigRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RealmServiceTest {

    private RealmConfigRepository repository;
    private RealmService service;

    @BeforeEach
    void setUp() {
        repository = mock(RealmConfigRepository.class);
        service = new RealmService(repository);
    }

    @Test
    void defaults_carryPlatformValues() {
        final RealmConfig d = RealmConfig.defaults("acme");
        assertEquals("acme", d.getRealmId());
        assertEquals(RealmConfig.DEFAULT_ACCESS_TOKEN_TTL_SECONDS, d.getAccessTokenTtlSeconds());
        assertEquals(RealmConfig.DEFAULT_REFRESH_TOKEN_TTL_SECONDS, d.getRefreshTokenTtlSeconds());
        assertEquals(RealmConfig.DEFAULT_PASSWORD_MIN_LENGTH, d.getPasswordMinLength());
        assertTrue(d.isEnabled());
        assertFalse(d.isRequireMfa());
        assertFalse(d.isReuseRefreshTokens());
    }

    @Test
    void getOrDefault_returnsTransientDefaults_whenAbsent() {
        when(repository.findById("ghost")).thenReturn(Optional.empty());

        final RealmConfig result = service.getOrDefault("ghost");

        assertEquals("ghost", result.getRealmId());
        assertEquals(RealmConfig.DEFAULT_ACCESS_TOKEN_TTL_SECONDS, result.getAccessTokenTtlSeconds());
        verify(repository, never()).save(any());
    }

    @Test
    void getOrDefault_returnsPersisted_whenPresent() {
        final RealmConfig stored = RealmConfig.defaults("acme");
        stored.setAccessTokenTtlSeconds(900);
        when(repository.findById("acme")).thenReturn(Optional.of(stored));

        assertSame(stored, service.getOrDefault("acme"));
    }

    @Test
    void createIfAbsent_persistsDefaultsWithDisplayName_whenAbsent() {
        when(repository.findById("acme")).thenReturn(Optional.empty());
        when(repository.save(any(RealmConfig.class))).thenAnswer(inv -> inv.getArgument(0));

        final RealmConfig created = service.createIfAbsent("acme", "ACME Corp");

        assertEquals("acme", created.getRealmId());
        assertEquals("ACME Corp", created.getDisplayName());
        assertEquals(RealmConfig.DEFAULT_REFRESH_TOKEN_TTL_SECONDS, created.getRefreshTokenTtlSeconds());
        verify(repository).save(any(RealmConfig.class));
    }

    @Test
    void createIfAbsent_isIdempotent_whenPresent() {
        final RealmConfig existing = RealmConfig.defaults("acme");
        when(repository.findById("acme")).thenReturn(Optional.of(existing));

        assertSame(existing, service.createIfAbsent("acme", "ignored"));
        verify(repository, never()).save(any());
    }

    @Test
    void list_returnsAllRealms() {
        when(repository.findAll()).thenReturn(java.util.List.of(RealmConfig.defaults("a"), RealmConfig.defaults("b")));
        assertEquals(2, service.list().size());
    }

    @Test
    void update_appliesMutatorAndPersists_whenPresent() {
        final RealmConfig existing = RealmConfig.defaults("acme");
        when(repository.findById("acme")).thenReturn(Optional.of(existing));
        when(repository.save(any(RealmConfig.class))).thenAnswer(inv -> inv.getArgument(0));

        final RealmConfig updated = service.update("acme", r -> {
            r.setRequireMfa(true);
            r.setAccessTokenTtlSeconds(900);
        });

        assertTrue(updated.isRequireMfa());
        assertEquals(900, updated.getAccessTokenTtlSeconds());
        verify(repository).save(existing);
    }

    @Test
    void update_returnsNull_whenAbsent() {
        when(repository.findById("ghost")).thenReturn(Optional.empty());
        assertEquals(null, service.update("ghost", r -> r.setRequireMfa(true)));
        verify(repository, never()).save(any());
    }

    @Test
    void ensureAdminRealm_createsMasterRealm() {
        when(repository.findById(RealmConfig.ADMIN_REALM_ID)).thenReturn(Optional.empty());
        when(repository.save(any(RealmConfig.class))).thenAnswer(inv -> inv.getArgument(0));

        final RealmConfig admin = service.ensureAdminRealm();

        assertEquals(RealmConfig.ADMIN_REALM_ID, admin.getRealmId());
        assertEquals("Master", admin.getDisplayName());
    }
}
