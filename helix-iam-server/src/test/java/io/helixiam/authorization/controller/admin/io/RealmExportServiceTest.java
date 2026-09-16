/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin.io;

import io.helixiam.authorization.amqp.application.ApplicationConfigPublisher;
import io.helixiam.authorization.amqp.authz.AuthorizationPublisher;
import io.helixiam.authorization.amqp.authz.AuthzPermissionDto;
import io.helixiam.authorization.amqp.authz.AuthzPolicyDto;
import io.helixiam.authorization.amqp.authz.AuthzResourceDto;
import io.helixiam.authorization.amqp.authz.AuthzScopeDto;
import io.helixiam.authorization.amqp.authz.AuthzServerDto;
import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.amqp.clientrole.ClientRoleDto;
import io.helixiam.authorization.amqp.clientrole.ClientRolePublisher;
import io.helixiam.authorization.amqp.clientrole.ServiceAccountRoleDto;
import io.helixiam.authorization.amqp.mapper.ClientMapperPublisher;
import io.helixiam.authorization.amqp.mapper.ProtocolMapperDto;
import io.helixiam.authorization.amqp.resource.ResourceIndicatorPublisher;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfigPublisher;
import io.helixiam.authorization.amqp.scim.ScimTargetConfigPublisher;
import io.helixiam.authorization.amqp.webhook.WebhookConfigPublisher;
import io.helixiam.authorization.amqp.workloadidentity.WorkloadIdentityConfigPublisher;
import io.helixiam.authorization.amqp.flow.FlowAdminPublisher;
import io.helixiam.authorization.amqp.flow.FlowDefinitionDto;
import io.helixiam.authorization.amqp.flow.FlowSummaryDto;
import io.helixiam.authorization.amqp.org.OrgDto;
import io.helixiam.authorization.amqp.org.OrganizationAdminPublisher;
import io.helixiam.authorization.amqp.realm.RealmAdminPublisher;
import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import io.helixiam.authorization.amqp.role.RoleAdminPublisher;
import io.helixiam.authorization.amqp.role.RoleDto;
import io.helixiam.authorization.amqp.saml.SamlRelyingPartyConfig;
import io.helixiam.authorization.amqp.saml.SamlRelyingPartyConfigPublisher;
import io.helixiam.authorization.amqp.scope.ClaimScopePublisher;
import io.helixiam.authorization.amqp.scope.ClientScopeDto;
import io.helixiam.authorization.amqp.scope.ScopeDetailDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM: the export service composes every per-domain publisher into one document and strips every
 * secret before it leaves. Exercised with mocked publishers.
 */
class RealmExportServiceTest {

    private RealmAdminPublisher realm;
    private ClientAdminPublisher clients;
    private SamlRelyingPartyConfigPublisher saml;
    private RoleAdminPublisher roles;
    private ClaimScopePublisher scopes;
    private IdentityProviderConfigPublisher idps;
    private FlowAdminPublisher flows;
    private OrganizationAdminPublisher orgs;
    private ClientMapperPublisher mapperPub;
    private ClientRolePublisher clientRolePub;
    private ResourceIndicatorPublisher resourcePub;
    private AuthorizationPublisher authzPub;
    private RealmExportService service;

    @BeforeEach
    void setUp() {
        realm = mock(RealmAdminPublisher.class);
        clients = mock(ClientAdminPublisher.class);
        saml = mock(SamlRelyingPartyConfigPublisher.class);
        roles = mock(RoleAdminPublisher.class);
        scopes = mock(ClaimScopePublisher.class);
        idps = mock(IdentityProviderConfigPublisher.class);
        flows = mock(FlowAdminPublisher.class);
        orgs = mock(OrganizationAdminPublisher.class);
        mapperPub = mock(ClientMapperPublisher.class);
        clientRolePub = mock(ClientRolePublisher.class);
        resourcePub = mock(ResourceIndicatorPublisher.class);
        authzPub = mock(AuthorizationPublisher.class);
        service = new RealmExportService(realm, clients, saml, roles, scopes, idps, flows, orgs,
                mock(ApplicationConfigPublisher.class), mock(WebhookConfigPublisher.class),
                mock(ScimTargetConfigPublisher.class), mock(WorkloadIdentityConfigPublisher.class),
                mock(io.helixiam.authorization.amqp.messaging.MessagingAdminPublisher.class),
                mock(io.helixiam.authorization.amqp.adminrbac.AdminRbacPublisher.class),
                mock(io.helixiam.authorization.amqp.group.GroupAdminPublisher.class),
                mock(io.helixiam.authorization.amqp.user.UserAdminPublisher.class),
                mapperPub, clientRolePub, resourcePub, authzPub,
                mock(io.helixiam.authorization.amqp.agent.AgentIdentityPublisher.class));

        when(realm.get("gov")).thenReturn(realmWithSecret());
        when(clients.list("gov")).thenReturn(List.of(clientWithSecret()));
        when(saml.list("gov")).thenReturn(List.of(new SamlRelyingPartyConfig("gov", "sp1", "https://acs",
                null, null, "CERTDATA", true, null, null)));
        when(roles.list("gov")).thenReturn(List.of(new RoleDto("gov", "r1", "admin")));
        when(scopes.scopes("gov")).thenReturn(List.of(new ClientScopeDto("gov", "s1", "profile", "Profile", 0, List.of())));
        when(scopes.scope(any())).thenReturn(new ScopeDetailDto("gov", "s1", "profile", "Profile", List.of()));
        when(idps.list("gov")).thenReturn(List.of(idpWithSecretConfig()));
        when(flows.list("gov")).thenReturn(List.of(new FlowSummaryDto("gov", "browser", true)));
        when(flows.getByAlias(any())).thenReturn(new FlowDefinitionDto("gov", "browser", true, List.of()));
        when(orgs.list("gov")).thenReturn(List.of(new OrgDto("gov", "o1", "acme", "Acme", List.of(), true, 0, null)));
    }

    @Test
    void export_assemblesEverySlice() {
        final RealmExportDocument doc = service.export("gov");

        assertThat(doc.formatVersion()).isEqualTo(RealmExportDocument.CURRENT_FORMAT_VERSION);
        assertThat(doc.realm()).isNotNull();
        assertThat(doc.clients()).hasSize(1);
        assertThat(doc.samlClients()).hasSize(1);
        assertThat(doc.roles()).hasSize(1);
        assertThat(doc.clientScopes()).hasSize(1);
        assertThat(doc.identityProviders()).hasSize(1);
        assertThat(doc.flows()).hasSize(1);
        assertThat(doc.organizations()).hasSize(1);
    }

    @Test
    void export_includesPerClientSlices_keyedByOAuthClientId() {
        // The single "gov" client ("web-app") has one of each per-client config domain.
        when(mapperPub.list(any())).thenReturn(List.of(new ProtocolMapperDto("m1", "gov", "web-app", "email-claim",
                "USER_ATTRIBUTE", "email", "email", true, true)));
        when(clientRolePub.listRoles(any())).thenReturn(List.of(new ClientRoleDto("r1", "gov", "web-app", "viewer",
                "Viewer")));
        when(clientRolePub.serviceAccountRoles(eq(io.helixiam.authorization.support.RealmScopedKey.pack("gov", "web-app"))))
                .thenReturn(List.of(new ServiceAccountRoleDto("s1", "gov", "web-app", "admin", "REALM", null)));
        when(resourcePub.allowedResourcesForClient(eq(io.helixiam.authorization.support.RealmScopedKey.pack("gov", "web-app"))))
                .thenReturn(List.of("https://api"));
        when(authzPub.getServer(any())).thenReturn(new AuthzServerDto("gov", "web-app", true, "UNANIMOUS"));
        when(authzPub.listScopes(any())).thenReturn(List.of(new AuthzScopeDto("sc1", "gov", "web-app", "read")));
        when(authzPub.listResources(any())).thenReturn(List.of(new AuthzResourceDto("rs1", "gov", "web-app", "doc",
                List.of("/d"), List.of("read"))));
        when(authzPub.listPolicies(any())).thenReturn(List.of(new AuthzPolicyDto("p1", "gov", "web-app", "viewers",
                "ROLE", "POSITIVE", List.of("viewer"))));
        when(authzPub.listPermissions(any())).thenReturn(List.of(new AuthzPermissionDto("pm1", "gov", "web-app",
                "read-doc", "scope", "doc", "read", List.of("viewers"), "UNANIMOUS")));

        final RealmExportDocument doc = service.export("gov");

        assertThat(doc.clientProtocolMappers()).hasSize(1);
        assertThat(doc.clientProtocolMappers().get(0).clientId()).isEqualTo("web-app");
        assertThat(doc.clientRoles()).hasSize(1);
        assertThat(doc.clientRoles().get(0).clientId()).isEqualTo("web-app");
        assertThat(doc.serviceAccountRoles()).hasSize(1);
        assertThat(doc.serviceAccountRoles().get(0).clientId()).isEqualTo("web-app");
        assertThat(doc.resourceIndicators()).hasSize(1);
        assertThat(doc.resourceIndicators().get(0).clientId()).isEqualTo("web-app");
        assertThat(doc.resourceIndicators().get(0).resources()).containsExactly("https://api");
        assertThat(doc.authorizationServices()).hasSize(1);
        assertThat(doc.authorizationServices().get(0).clientId()).isEqualTo("web-app");
        assertThat(doc.authorizationServices().get(0).scopes()).hasSize(1);
        assertThat(doc.authorizationServices().get(0).permissions()).hasSize(1);
    }

    @Test
    void export_omitsAuthorizationServices_whenClientHasNone() {
        // default mocks: authz server is null/disabled and all lists empty → no ClientAuthorizationDto emitted.
        final RealmExportDocument doc = service.export("gov");
        assertThat(doc.authorizationServices()).isEmpty();
        assertThat(doc.resourceIndicators()).isEmpty();
    }

    @Test
    void export_masksClientSecret() {
        assertThat(service.export("gov").clients().get(0).secret()).isNull();
    }

    @Test
    void export_emitsCaptchaSecretAsEnvPlaceholder() {
        final RealmExportDocument doc = service.export("gov");
        final RealmSettingsDto out = doc.realm();
        assertThat(out.captchaSecretKey()).isEqualTo("${HELIX_GOV_CAPTCHA_SECRET}"); // placeholder, never the literal
        assertThat(out.captchaSiteKey()).isEqualTo("site-key");                       // non-secret kept
        assertThat(doc.requiredEnv()).contains("HELIX_GOV_CAPTCHA_SECRET");
    }

    @Test
    void export_emitsSecretIdpConfigKeysAsPlaceholders_keepsNonSecrets() {
        final RealmExportDocument doc = service.export("gov");
        final Map<String, String> config = doc.identityProviders().get(0).config();
        // secret keys are kept but carry an env placeholder instead of the literal value
        assertThat(config).containsEntry("clientSecret", "${HELIX_GOV_IDP_GOOGLE_CLIENTSECRET}");
        assertThat(config.get("bindCredential")).startsWith("${HELIX_GOV_IDP_GOOGLE_");
        assertThat(config).containsEntry("clientId", "abc").containsEntry("authorizationUrl", "https://idp/auth");
        assertThat(doc.requiredEnv()).contains("HELIX_GOV_IDP_GOOGLE_CLIENTSECRET");
    }

    @Test
    void export_toleratesNullSlices() {
        when(clients.list(eq("empty"))).thenReturn(null);
        when(roles.list(eq("empty"))).thenReturn(null);
        when(saml.list(eq("empty"))).thenReturn(null);
        when(scopes.scopes(eq("empty"))).thenReturn(null);
        when(idps.list(eq("empty"))).thenReturn(null);
        when(flows.list(eq("empty"))).thenReturn(null);
        when(orgs.list(eq("empty"))).thenReturn(null);
        when(realm.get("empty")).thenReturn(null);

        final RealmExportDocument doc = service.export("empty");
        assertThat(doc.clients()).isEmpty();
        assertThat(doc.realm()).isNull();
    }

    private static RealmSettingsDto realmWithSecret() {
        return new RealmSettingsDto("gov", "Gov", "https://issuer", 300, 3600, false, false, 8, true,
                1800, 36000, false, 0, false, 5, 900, 900, false, false, false, false, false, false, 0, false,
                "recaptcha", "site-key", "SUPER-SECRET", 0, false, false, 0, 0, "none", "none", "none",
                null, null, null, null, null, true);
    }

    private static ClientDto clientWithSecret() {
        return new ClientDto("gov", "id1", "web-app", List.of("authorization_code"), List.of("https://cb"),
                List.of("openid"), "TOP-SECRET", "sub", null, "Web", null, List.of(), List.of(), false, false,
                false, null, null, null, null, false, null, null, null, false, null, null, null, null, null, null, null, null);
    }

    private static IdentityProviderConfig idpWithSecretConfig() {
        final Map<String, String> config = new java.util.LinkedHashMap<>();
        config.put("clientId", "abc");
        config.put("clientSecret", "shh");
        config.put("bindCredential", "pw");
        config.put("password", "pw2");
        config.put("authorizationUrl", "https://idp/auth");
        return new IdentityProviderConfig("gov", "google", "oidc", "Google", true, config);
    }
}
