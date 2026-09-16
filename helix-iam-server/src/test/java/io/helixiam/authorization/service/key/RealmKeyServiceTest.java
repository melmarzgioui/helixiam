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
        when(repository.findFirstByRealmIdAndStatusOrderByCreationDateDesc("acme", "ACTIVE"))
                .thenReturn(Optional.of(current));
        when(keyProvider.generate())
                .thenReturn(new SigningKeyProvider.GeneratedKey("new", "RSA", "pub", "priv"));

        final RealmKey rotated = service.rotate("acme");

        assertEquals("new", rotated.getKeyId());
        assertTrue(rotated.isActive());
        assertEquals("ROTATED", current.getStatus());
        assertNotNull(current.getRotatedDate());
        verify(repository, times(2)).save(any(RealmKey.class)); // demote old + save new
    }

    @Test
    void verificationKeys_returnsActiveAndRotated() {
        when(repository.findAllByRealmIdAndStatusIn(eq("acme"), any()))
                .thenReturn(List.of(activeKey("a", "acme"), activeKey("b", "acme")));

        assertEquals(2, service.verificationKeys("acme").size());
    }

    @Test
    void retire_marksKeyRetired_andReportsTrue() {
        final RealmKey key = activeKey("k", "acme");
        when(repository.findById("k")).thenReturn(Optional.of(key));

        final boolean retired = service.retire("k");

        assertTrue(retired);
        assertEquals("RETIRED", key.getStatus());
        verify(repository).save(key);
    }

    @Test
    void retire_reportsFalse_whenKeyMissing() {
        when(repository.findById("nope")).thenReturn(Optional.empty());

        assertFalse(service.retire("nope"));
        verify(repository, never()).save(any(RealmKey.class));
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
        assertEquals("RSA", views.get(0).algorithm());
        assertEquals("pub-a", views.get(0).publicKey()); // public material only
        assertEquals("ROTATED", views.get(1).status());
    }
}
