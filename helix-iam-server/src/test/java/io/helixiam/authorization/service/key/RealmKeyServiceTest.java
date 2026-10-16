/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import io.helixiam.authorization.domain.realm.RealmKey;
import io.helixiam.authorization.domain.realm.RealmKeyView;
import io.helixiam.authorization.repository.realm.RealmKeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RealmKeyServiceTest {

    private RealmKeyRepository repository;
    private SigningKeyProvider keyProvider;
    private RealmKeyService service;

    @BeforeEach
    void setUp() {
        repository = mock(RealmKeyRepository.class);
        keyProvider = mock(SigningKeyProvider.class);
        when(keyProvider.type()).thenReturn("software");
        service = new RealmKeyService(repository, keyProvider);
        when(repository.save(any(RealmKey.class))).thenAnswer(inv -> inv.getArgument(0));
    }

    private RealmKey activeKey(final String kid, final String realm) {
        return new RealmKey(kid, realm, "RSA", "pub-" + kid, "priv-" + kid);
    }

    @Test
    void getOrCreateActive_returnsExisting_withoutGenerating() {
        final RealmKey existing = activeKey("k1", "acme");
        when(repository.findFirstByRealmIdAndStatusOrderByCreationDateDesc("acme", "ACTIVE"))
                .thenReturn(Optional.of(existing));

        assertSame(existing, service.getOrCreateActive("acme"));
        verify(keyProvider, never()).generate();
    }

    @Test
    void getOrCreateActive_generatesAndPersists_whenAbsent() {
        when(repository.findFirstByRealmIdAndStatusOrderByCreationDateDesc("acme", "ACTIVE"))
                .thenReturn(Optional.empty());
        when(keyProvider.generate())
                .thenReturn(new SigningKeyProvider.GeneratedKey("k2", "RSA", "pub", "priv"));

        final RealmKey created = service.getOrCreateActive("acme");

        assertEquals("k2", created.getKeyId());
        assertTrue(created.isActive());
        verify(repository).save(any(RealmKey.class));
    }

    @Test
    void rotate_demotesCurrentActive_andGeneratesNewActive() {
        final RealmKey current = activeKey("old", "acme");
        when(repository.findAllByRealmIdAndStatusIn("acme", List.of("ACTIVE"))).thenReturn(List.of(current));
        when(keyProvider.generate())
                .thenReturn(new SigningKeyProvider.GeneratedKey("new", "RSA", "pub", "priv"));

        final RealmKey rotated = service.rotate("acme");

        assertEquals("new", rotated.getKeyId());
        assertTrue(rotated.isActive());
        assertEquals("RS256", rotated.getAlgorithm());
        assertNotNull(rotated.getActivatedDate());
        assertEquals("ROTATED", current.getStatus());
        assertNotNull(current.getRotatedDate());
        verify(repository, times(2)).save(any(RealmKey.class)); // demote old + save new
    }

    @Test
    void rotate_es256_usesTheProvidersEcKey_andRefusesUnknownAlgorithms() {
        when(repository.findAllByRealmIdAndStatusIn("acme", List.of("ACTIVE"))).thenReturn(List.of());
        when(keyProvider.generate("ES256"))
                .thenReturn(new SigningKeyProvider.GeneratedKey("ec", "ES256", "pub", "priv"));
        assertEquals("ES256", service.rotate("acme", "ES256").getAlgorithm());
        org.junit.jupiter.api.Assertions.assertThrows(KeyImportException.class, () -> service.rotate("acme", "HS256"));
    }

    @Test
    void activate_onlyPending_demotesTheActiveKey() {
        final RealmKey current = activeKey("old", "acme");
        final RealmKey pending = activeKey("p", "acme");
        pending.setStatus(RealmKey.Status.PENDING);
        when(repository.findByKeyIdAndRealmId("p", "acme")).thenReturn(Optional.of(pending));
        when(repository.findByKeyIdAndRealmId("old", "acme")).thenReturn(Optional.of(current));
        when(repository.findAllByRealmIdAndStatusIn("acme", List.of("ACTIVE"))).thenReturn(List.of(current));

        final RealmKey activated = service.activate("acme", "p");

        assertEquals("ACTIVE", activated.getStatus());
        assertNotNull(activated.getActivatedDate());
        assertEquals("ROTATED", current.getStatus());
        org.junit.jupiter.api.Assertions.assertThrows(RealmKeyService.KeyStateException.class,
                () -> service.activate("acme", "old"));
        org.junit.jupiter.api.Assertions.assertThrows(java.util.NoSuchElementException.class,
                () -> service.activate("acme", "missing"));
    }

    @Test
    void importAndCsr_areRefusedWithoutDbEncryption_outsideDev() {
        final RealmKeyService unencrypted = new RealmKeyService(repository, keyProvider, false,
                io.helixiam.common.startup.DeploymentProfile.production(), null);
        final KeyImportException e = org.junit.jupiter.api.Assertions.assertThrows(KeyImportException.class,
                () -> unencrypted.importKey("acme", "x", "y"));
        assertTrue(e.getMessage().contains("DB_ENCRYPTION"));
        org.junit.jupiter.api.Assertions.assertThrows(KeyImportException.class,
                () -> unencrypted.createCsr("acme", "RS256", "CN=x", List.of()));
    }

    @Test
    void verificationKeys_returnsActiveAndRotated() {
        when(repository.findAllByRealmIdAndStatusIn(eq("acme"), any()))
                .thenReturn(List.of(activeKey("a", "acme"), activeKey("b", "acme")));

        assertEquals(2, service.verificationKeys("acme").size());
    }

    @Test
    void retire_marksKeyRetired_butRefusesTheActiveKey() {
        final RealmKey key = activeKey("k", "acme");
        key.setStatus(RealmKey.Status.ROTATED);
        when(repository.findByKeyIdAndRealmId("k", "acme")).thenReturn(Optional.of(key));
        final RealmKey active = activeKey("a", "acme");
        when(repository.findByKeyIdAndRealmId("a", "acme")).thenReturn(Optional.of(active));

        assertEquals(RealmKeyService.RetireOutcome.RETIRED, service.retire("acme", "k"));
        assertEquals("RETIRED", key.getStatus());
        verify(repository).save(key);
        assertEquals(RealmKeyService.RetireOutcome.ACTIVE_REFUSED, service.retire("acme", "a"));
        assertEquals("ACTIVE", active.getStatus());
    }

    @Test
    void retire_reportsNotFound_forAMissingKeyOrAnotherRealmsKey() {
        when(repository.findByKeyIdAndRealmId(any(), any())).thenReturn(Optional.empty());

        assertEquals(RealmKeyService.RetireOutcome.NOT_FOUND, service.retire("acme", "nope"));
        verify(repository, never()).save(any(RealmKey.class));
        assertFalse(service.find("acme", "").isPresent());
    }

    @Test
    void listViews_mapsEveryKeyNewestFirst_andNeverExposesPrivateKey() {
        final RealmKey active = activeKey("a", "acme");
        final RealmKey rotated = activeKey("b", "acme");
        rotated.setStatus(RealmKey.Status.ROTATED);
        when(repository.findAllByRealmIdOrderByCreationDateDesc("acme"))
                .thenReturn(List.of(active, rotated));

        final List<RealmKeyView> views = service.listViews("acme");

        assertEquals(2, views.size());
        assertEquals("a", views.get(0).keyId());
        assertEquals("ACTIVE", views.get(0).status());
        assertEquals("RS256", views.get(0).algorithm()); // rc.11 "RSA" reads as RS256
        assertEquals("pub-a", views.get(0).publicKey()); // public material only
        assertEquals("ROTATED", views.get(1).status());
    }
}
