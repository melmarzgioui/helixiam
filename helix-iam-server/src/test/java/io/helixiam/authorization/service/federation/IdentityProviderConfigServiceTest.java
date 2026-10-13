/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.federation;

import io.helixiam.authorization.domain.federation.IdentityProviderConfig;
import io.helixiam.authorization.domain.federation.IdentityProviderEntity;
import io.helixiam.authorization.repository.federation.IdentityProviderConfigRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E8.1: persistence service for per-realm identity-provider configs.
 */
class IdentityProviderConfigServiceTest {

    private IdentityProviderConfigRepository repository;
    private IdentityProviderConfigService service;

    @BeforeEach
    void setUp() {
        repository = mock(IdentityProviderConfigRepository.class);
        service = new IdentityProviderConfigService(repository);
    }

    @Test
    void saveOrUpdate_persistsEntityKeyedByRealmAndAlias_withConfigSerialised() {
        when(repository.save(any(IdentityProviderEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        final IdentityProviderConfig cfg = new IdentityProviderConfig(
                "gov", "digid", "saml", "DigiD (CombiConnect)", true,
                Map.of("ssoUrl", "https://digid.example/sso", "spEntityId", "https://helix.example/sp"));

        final IdentityProviderConfig saved = service.saveOrUpdate(cfg);

        final ArgumentCaptor<IdentityProviderEntity> captor = ArgumentCaptor.forClass(IdentityProviderEntity.class);
        verify(repository).save(captor.capture());
        final IdentityProviderEntity entity = captor.getValue();
        assertEquals("gov|digid", entity.getId());
        assertEquals("gov", entity.getRealmId());
        assertEquals("digid", entity.getAlias());
        assertEquals("saml", entity.getProtocol());
        assertTrue(entity.getConfigJson().contains("ssoUrl"), "config map should be serialised to JSON");

        assertEquals("digid", saved.alias());
        assertEquals("https://digid.example/sso", saved.config().get("ssoUrl"));
    }

    @Test
    void list_returnsConfigsForRealm_withConfigDeserialised() {
        when(repository.findAllByRealmId("gov"))
                .thenReturn(List.of(entity("gov", "digid", "saml", "DigiD", true, "{\"ssoUrl\":\"https://idp\"}")));

        final List<IdentityProviderConfig> list = service.list("gov");

        assertEquals(1, list.size());
        assertEquals("digid", list.get(0).alias());
        assertEquals("https://idp", list.get(0).config().get("ssoUrl"));
    }

    @Test
    void get_returnsConfig_whenPresent_andEmpty_whenAbsent() {
        when(repository.findByRealmIdAndAlias("gov", "digid"))
                .thenReturn(Optional.of(entity("gov", "digid", "saml", "DigiD", true, "{}")));
        when(repository.findByRealmIdAndAlias("gov", "ghost")).thenReturn(Optional.empty());

        assertTrue(service.get("gov", "digid").isPresent());
        assertTrue(service.get("gov", "ghost").isEmpty());
    }

    @Test
    void delete_removes_whenPresent_andReturnsFalse_whenAbsent() {
        when(repository.existsByRealmIdAndAlias("gov", "digid")).thenReturn(true);
        when(repository.existsByRealmIdAndAlias("gov", "ghost")).thenReturn(false);

        assertTrue(service.delete("gov", "digid"));
        verify(repository).deleteByRealmIdAndAlias("gov", "digid");

        assertFalse(service.delete("gov", "ghost"));
        verify(repository, never()).deleteByRealmIdAndAlias("gov", "ghost");
    }

    @Test
    void saveOrUpdate_storesSecretsOutsideConfigJson_andReadMergesThemBack() {
        when(repository.save(any(IdentityProviderEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        final IdentityProviderConfig saved = service.saveOrUpdate(new IdentityProviderConfig("gov", "up", "oidc", "Up",
                true, Map.of("clientId", "web", "clientSecret", "s3cret", "clientSecretSet", "true")));

        final ArgumentCaptor<IdentityProviderEntity> captor = ArgumentCaptor.forClass(IdentityProviderEntity.class);
        verify(repository).save(captor.capture());
        assertEquals("{\"clientId\":\"web\"}", captor.getValue().getConfigJson());
        assertEquals("{\"clientSecret\":\"s3cret\"}", captor.getValue().getSecretJson());
        assertEquals("s3cret", saved.config().get("clientSecret"), "the runtime map is merged");
        assertFalse(saved.config().containsKey("clientSecretSet"));
    }

    @Test
    void saveOrUpdate_absentOrBlankSecret_keepsTheStoredOne_andClearRemovesIt() {
        final IdentityProviderEntity stored = entity("gov", "up", "oidc", "Up", true, "{\"clientId\":\"web\"}");
        stored.setSecretJson("{\"clientSecret\":\"s3cret\"}");
        when(repository.findById("gov|up")).thenReturn(Optional.of(stored));
        when(repository.save(any(IdentityProviderEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        service.saveOrUpdate(new IdentityProviderConfig("gov", "up", "oidc", "Up", true, Map.of("clientId", "web2")));
        assertEquals("{\"clientSecret\":\"s3cret\"}", stored.getSecretJson());
        service.saveOrUpdate(new IdentityProviderConfig("gov", "up", "oidc", "Up", true,
                Map.of("clientId", "web2", "clientSecret", " ")));
        assertEquals("{\"clientSecret\":\"s3cret\"}", stored.getSecretJson());

        final IdentityProviderConfig cleared = service.saveOrUpdate(new IdentityProviderConfig("gov", "up", "oidc",
                "Up", true, Map.of("clientId", "web2", "clientSecret", "", "clearClientSecret", "true")));
        assertEquals(null, stored.getSecretJson());
        assertFalse(cleared.config().containsKey("clientSecret"));
        assertEquals("{\"clientId\":\"web2\"}", stored.getConfigJson());
    }

    @Test
    void read_legacySecretStillInConfigJson_isMergedForTheRuntime_andMovedOnTheNextSave() {
        final IdentityProviderEntity legacy = entity("gov", "up", "oidc", "Up", true,
                "{\"clientId\":\"web\",\"clientSecret\":\"old\"}");
        when(repository.findByRealmIdAndAlias("gov", "up")).thenReturn(Optional.of(legacy));
        when(repository.findById("gov|up")).thenReturn(Optional.of(legacy));
        when(repository.save(any(IdentityProviderEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        assertEquals("old", service.get("gov", "up").orElseThrow().config().get("clientSecret"));
        service.saveOrUpdate(new IdentityProviderConfig("gov", "up", "oidc", "Up", true, Map.of("clientId", "web")));
        assertEquals("{\"clientId\":\"web\"}", legacy.getConfigJson());
        assertEquals("{\"clientSecret\":\"old\"}", legacy.getSecretJson());
    }

    // --- final review m3 / F1: one unreadable row never takes down the realm (or, at startup, every realm) ---

    @Test
    void list_skipsARowWhoseSecretsCannotBeRead_andReturnsTheRest() {
        final IdentityProviderEntity broken = entity("gov", "broken", "oidc", "Broken", true, "{}");
        broken.setSecretJson("not-json-and-not-decryptable");
        when(repository.findAllByRealmId("gov"))
                .thenReturn(List.of(entity("gov", "ok", "saml", "OK", true, "{}"), broken));

        final List<IdentityProviderConfig> list = service.list("gov");

        assertEquals(List.of("ok"), list.stream().map(IdentityProviderConfig::alias).toList());
    }

    @Test
    void list_whenLoadingTheRealmFails_loadsRowByRow_skippingTheUnreadableOne() {
        // e.g. the entity converter refusing an undecryptable secret_json fails the whole query
        when(repository.findAllByRealmId("gov")).thenThrow(new IllegalStateException("cannot decrypt"));
        when(repository.findIdsByRealmId("gov")).thenReturn(List.of("gov|ok", "gov|broken"));
        when(repository.findById("gov|ok")).thenReturn(Optional.of(entity("gov", "ok", "saml", "OK", true, "{}")));
        when(repository.findById("gov|broken")).thenThrow(new IllegalStateException("cannot decrypt"));

        final List<IdentityProviderConfig> list = service.list("gov");

        assertEquals(List.of("ok"), list.stream().map(IdentityProviderConfig::alias).toList());
    }

    @Test
    void listAll_returnsTheConfigsOfEveryRealm_skippingAnUnreadableRow() {
        when(repository.findAll()).thenThrow(new IllegalStateException("cannot decrypt"));
        when(repository.findAllIds()).thenReturn(List.of("a|one", "b|two", "b|bad"));
        when(repository.findById("a|one")).thenReturn(Optional.of(entity("a", "one", "oidc", "One", true, "{}")));
        when(repository.findById("b|two")).thenReturn(Optional.of(entity("b", "two", "oidc", "Two", true, "{}")));
        when(repository.findById("b|bad")).thenThrow(new IllegalStateException("cannot decrypt"));

        final List<IdentityProviderConfig> all = service.listAll();

        assertEquals(List.of("a/one", "b/two"), all.stream().map(c -> c.realmId() + "/" + c.alias()).toList());
    }

    /**
     * A PUT that changes the protocol drops the stored secrets the new protocol does not use: an OIDC client secret
     * must not linger (encrypted, never read again) on what is now an LDAP or SAML connection.
     */
    @Test
    void changingTheProtocol_dropsTheOldProtocolsSecrets_keepsTheNewOnes() {
        final IdentityProviderEntity stored = entity("gov", "corp", "oidc", "Corp", true, "{\"issuer\":\"https://idp\"}");
        stored.setSecretJson("{\"clientSecret\":\"old-oidc-secret\"}");
        when(repository.findById("gov|corp")).thenReturn(Optional.of(stored));
        when(repository.save(any(IdentityProviderEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        service.saveOrUpdate(new IdentityProviderConfig("gov", "corp", "ldap", "Corp", true,
                Map.of("url", "ldaps://dc.example:636", "bindPassword", "new-bind-secret")));

        final ArgumentCaptor<IdentityProviderEntity> captor = ArgumentCaptor.forClass(IdentityProviderEntity.class);
        verify(repository).save(captor.capture());
        final String secrets = captor.getValue().getSecretJson();
        assertFalse(secrets.contains("clientSecret"), "the OIDC secret is dropped: " + secrets);
        assertTrue(secrets.contains("new-bind-secret"), "the new protocol's secret is kept");
    }

    @Test
    void changingToAProtocolWithoutSecrets_dropsThemAll() {
        final IdentityProviderEntity stored = entity("gov", "corp", "oidc", "Corp", true, "{}");
        stored.setSecretJson("{\"clientSecret\":\"old-oidc-secret\"}");
        when(repository.findById("gov|corp")).thenReturn(Optional.of(stored));
        when(repository.save(any(IdentityProviderEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        service.saveOrUpdate(new IdentityProviderConfig("gov", "corp", "saml", "Corp", true,
                Map.of("ssoUrl", "https://idp/sso")));

        final ArgumentCaptor<IdentityProviderEntity> captor = ArgumentCaptor.forClass(IdentityProviderEntity.class);
        verify(repository).save(captor.capture());
        assertEquals(null, captor.getValue().getSecretJson());
    }

    @Test
    void theSameProtocol_keepsAStoredSecretTheWriteLeavesOut() {
        final IdentityProviderEntity stored = entity("gov", "corp", "OIDC", "Corp", true, "{}");
        stored.setSecretJson("{\"clientSecret\":\"kept\"}");
        when(repository.findById("gov|corp")).thenReturn(Optional.of(stored));
        when(repository.save(any(IdentityProviderEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        service.saveOrUpdate(new IdentityProviderConfig("gov", "corp", "oidc", "Corp", true,
                Map.of("issuer", "https://idp")));

        final ArgumentCaptor<IdentityProviderEntity> captor = ArgumentCaptor.forClass(IdentityProviderEntity.class);
        verify(repository).save(captor.capture());
        assertTrue(captor.getValue().getSecretJson().contains("kept"));
    }

    private static IdentityProviderEntity entity(final String realm, final String alias, final String protocol,
                                                 final String displayName, final boolean enabled, final String json) {
        final IdentityProviderEntity e = new IdentityProviderEntity();
        e.setId(IdentityProviderEntity.key(realm, alias));
        e.setRealmId(realm);
        e.setAlias(alias);
        e.setProtocol(protocol);
        e.setDisplayName(displayName);
        e.setEnabled(enabled);
        e.setConfigJson(json);
        return e;
    }
}
