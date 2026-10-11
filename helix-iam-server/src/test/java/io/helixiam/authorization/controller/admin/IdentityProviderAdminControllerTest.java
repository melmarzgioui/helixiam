/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfigPublisher;
import io.helixiam.authorization.amqp.federation.IdentityProviderRef;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E8.2: admin REST API for identity-provider CRUD. The realm always comes from the path,
 * never the body, so a connection cannot be written into another realm.
 */
class IdentityProviderAdminControllerTest {

    private IdentityProviderConfigPublisher publisher;
    private IdentityProviderAdminController controller;

    @BeforeEach
    void setUp() {
        publisher = mock(IdentityProviderConfigPublisher.class);
        controller = new IdentityProviderAdminController(publisher);
    }

    @Test
    void list_delegatesToPublisherForThatRealm() {
        final IdentityProviderConfig cfg = new IdentityProviderConfig("gov", "digid", "saml", "DigiD", true, Map.of());
        when(publisher.list("gov")).thenReturn(List.of(cfg));

        final List<IdentityProviderAdminView> result = controller.list("gov");

        assertThat(result).containsExactly(IdentityProviderAdminView.of(cfg));
        verify(publisher).list("gov");
    }

    @Test
    void get_returns200_whenPresent_and404_whenAbsent() {
        final IdentityProviderConfig cfg = new IdentityProviderConfig("gov", "digid", "saml", "DigiD", true, Map.of());
        when(publisher.get(new IdentityProviderRef("gov", "digid"))).thenReturn(cfg);
        when(publisher.get(new IdentityProviderRef("gov", "ghost"))).thenReturn(null);

        assertThat(controller.get("gov", "digid").getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(controller.get("gov", "digid").getBody()).isEqualTo(IdentityProviderAdminView.of(cfg));
        assertThat(controller.get("gov", "ghost").getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void create_buildsConfigFromPathRealm_ignoringAnyBodyRealm_andReturns201() {
        when(publisher.save(any(IdentityProviderConfig.class))).thenAnswer(inv -> inv.getArgument(0));
        final IdentityProviderRequest body = new IdentityProviderRequest(
                "digid", "saml", "DigiD (CombiConnect)", true, Map.of("ssoUrl", "https://idp"));

        final ResponseEntity<IdentityProviderAdminView> response = controller.create("gov", body);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        final ArgumentCaptor<IdentityProviderConfig> captor = ArgumentCaptor.forClass(IdentityProviderConfig.class);
        verify(publisher).save(captor.capture());
        final IdentityProviderConfig sent = captor.getValue();
        assertThat(sent.realmId()).isEqualTo("gov");
        assertThat(sent.alias()).isEqualTo("digid");
        assertThat(sent.config()).containsEntry("ssoUrl", "https://idp");
    }

    @Test
    void update_usesAliasFromPath_andSaves() {
        when(publisher.save(any(IdentityProviderConfig.class))).thenAnswer(inv -> inv.getArgument(0));
        final IdentityProviderRequest body = new IdentityProviderRequest(
                "ignored-alias", "saml", "DigiD", false, Map.of());

        final ResponseEntity<IdentityProviderAdminView> response = controller.update("gov", "digid", body);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        final ArgumentCaptor<IdentityProviderConfig> captor = ArgumentCaptor.forClass(IdentityProviderConfig.class);
        verify(publisher).save(captor.capture());
        assertThat(captor.getValue().alias()).isEqualTo("digid");
        assertThat(captor.getValue().enabled()).isFalse();
    }

    @Test
    void delete_returns204_whenRemoved_and404_whenAbsent() {
        when(publisher.delete(new IdentityProviderRef("gov", "digid"))).thenReturn(Boolean.TRUE);
        when(publisher.delete(new IdentityProviderRef("gov", "ghost"))).thenReturn(Boolean.FALSE);

        assertThat(controller.delete("gov", "digid").getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(controller.delete("gov", "ghost").getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void responses_neverCarrySecretValues_onlyKeySetFlags() {
        final IdentityProviderConfig oidc = new IdentityProviderConfig("gov", "up", "oidc", "Up", true,
                Map.of("clientId", "web", "clientSecret", "s3cret"));
        final IdentityProviderConfig eid = new IdentityProviderConfig("gov", "digid", "digid", "DigiD", true,
                Map.of("ssoUrl", "https://idp", "spSigningPrivateKey", "PEM"));
        when(publisher.list("gov")).thenReturn(List.of(oidc, eid));
        when(publisher.get(new IdentityProviderRef("gov", "up"))).thenReturn(oidc);
        when(publisher.save(any(IdentityProviderConfig.class))).thenReturn(oidc);

        final List<IdentityProviderAdminView> list = controller.list("gov");
        assertThat(list.get(0).config()).containsEntry("clientId", "web").containsEntry("clientSecretSet", true)
                .doesNotContainKey("clientSecret");
        assertThat(list.get(1).config()).containsEntry("spSigningPrivateKeySet", true)
                .containsEntry("spDecryptionPrivateKeySet", false).doesNotContainKey("spSigningPrivateKey");
        assertThat(controller.get("gov", "up").getBody().config()).doesNotContainKey("clientSecret");
        assertThat(controller.create("gov", new IdentityProviderRequest("up", "oidc", "Up", true,
                Map.of("clientSecret", "s3cret"))).getBody().config()).doesNotContainKey("clientSecret")
                .containsEntry("clientSecretSet", true);
    }

    @Test
    void aNewSecretTogetherWithItsClearFlag_isRejected_andNothingIsSaved() {
        final IdentityProviderRequest body = new IdentityProviderRequest("up", "oidc", "Up", true,
                Map.of("clientSecret", "new", "clearClientSecret", "true"));

        assertThatThrownBy(() -> controller.update("gov", "up", body))
                .isInstanceOf(ProviderValidationException.class)
                .satisfies(e -> assertThat(((ProviderValidationException) e).fieldErrors())
                        .containsKey("config.clearClientSecret"));
        verify(publisher, never()).save(any(IdentityProviderConfig.class));
    }
}
