/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin.io;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.helixiam.authorization.amqp.adminrbac.AdminRoleGrantsDto;
import io.helixiam.authorization.amqp.application.ApplicationConfig;
import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.amqp.clientrole.ClientRoleDto;
import io.helixiam.authorization.amqp.clientrole.ServiceAccountRoleDto;
import io.helixiam.authorization.amqp.mapper.ProtocolMapperDto;
import io.helixiam.authorization.amqp.resource.AllowedResourcesWrite;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.amqp.flow.FlowDefinitionDto;
import io.helixiam.authorization.amqp.group.GroupDto;
import io.helixiam.authorization.amqp.messaging.MessageTemplateDto;
import io.helixiam.authorization.amqp.messaging.MessagingProviderWriteDto;
import io.helixiam.authorization.amqp.org.OrgDto;
import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import io.helixiam.authorization.amqp.role.RoleDto;
import io.helixiam.authorization.amqp.saml.SamlRelyingPartyConfig;
import io.helixiam.authorization.amqp.scim.ScimTargetDto;
import io.helixiam.authorization.amqp.scope.ScopeDetailDto;
import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.amqp.webhook.WebhookSubscriptionDto;
import io.helixiam.authorization.amqp.workloadidentity.WorkloadIdentityCredentialDto;

import java.util.List;

/**
 * Helix IAM: a single-document export/import of one realm's configuration. Bundles every
 * configurable slice that the admin console manages. Secrets are masked or omitted on export (see
 * {@link RealmExportService}); on import, missing/blank secrets are simply left for the operator to set
 * afterwards (we never write a masked placeholder as a real credential).
 *
 * <p>This is the wire shape for {@code GET /admin/realms/{realm}/export} and the request body for
 * {@code POST /admin/realms/{realm}/import}. It is purely a publisher-side orchestration object — it
 * crosses no AMQP exchange of its own; each slice is read/written through the existing per-domain
 * publishers. {@code @JsonIgnoreProperties(ignoreUnknown = true)} lets a document exported by a newer
 * version still import into an older one. Null/empty collections are dropped on serialisation so an
 * export stays compact and a hand-edited import can omit slices it does not wish to touch.
 *
 * @param formatVersion bumped when the document shape changes incompatibly (currently {@code 1})
 * @param realm         the realm's own settings (secrets masked)
 * @param clients       OIDC clients (secrets masked)
 * @param samlClients   SAML relying parties
 * @param roles         realm roles (by name)
 * @param clientScopes  client scopes with their claim lists
 * @param identityProviders federation / identity providers (config-map secrets masked)
 * @param flows         authentication flows (by alias) with their full execution trees
 * @param organizations realm organizations (by name)
 * @param theme         the realm's structured theme layer (asset references only, never asset bytes)
 * @param organizationThemes organization theme layers, keyed by organization name
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record RealmExportDocument(Integer formatVersion,
                                  RealmSettingsDto realm,
                                  List<ClientDto> clients,
                                  List<SamlRelyingPartyConfig> samlClients,
                                  List<RoleDto> roles,
                                  List<ScopeDetailDto> clientScopes,
                                  List<IdentityProviderConfig> identityProviders,
                                  List<FlowDefinitionDto> flows,
                                  List<OrgDto> organizations,
                                  List<ApplicationConfig> applications,
                                  List<WebhookSubscriptionDto> webhooks,
                                  List<ScimTargetDto> scimTargets,
                                  List<WorkloadIdentityCredentialDto> workloadIdentity,
                                  List<MessagingProviderWriteDto> messagingProviders,
                                  List<MessageTemplateDto> messageTemplates,
                                  List<AdminRoleGrantsDto> adminRoles,
                                  List<GroupDto> groups,
                                  List<UserAdminDto> users,
                                  List<ProtocolMapperDto> clientProtocolMappers,
                                  List<ClientRoleDto> clientRoles,
                                  List<ServiceAccountRoleDto> serviceAccountRoles,
                                  List<AllowedResourcesWrite> resourceIndicators,
                                  List<ClientAuthorizationDto> authorizationServices,
                                  List<io.helixiam.authorization.amqp.agent.AgentIdentityDto> agents,
                                  List<String> requiredEnv,
                                  @com.fasterxml.jackson.databind.annotation.JsonDeserialize(
                                          using = io.helixiam.authorization.theme.StrictThemeDeserializer.class)
                                  io.helixiam.authorization.theme.Theme theme,
                                  List<OrganizationThemeExport> organizationThemes) {

    /**
     * The current document format version. v2 added the {@code requiredEnv} manifest, switched secret
     * masking from null-omission to {@code ${ENV_VAR}} placeholders, and grows additively with new config
     * slices (applications, webhooks, SCIM targets, workload identity, …); v1 documents still import.
     */
    public static final int CURRENT_FORMAT_VERSION = 2;

    /** Back-compat constructor (every slice before structured theming). */
    public RealmExportDocument(final Integer formatVersion, final RealmSettingsDto realm,
                               final List<ClientDto> clients, final List<SamlRelyingPartyConfig> samlClients,
                               final List<RoleDto> roles, final List<ScopeDetailDto> clientScopes,
                               final List<IdentityProviderConfig> identityProviders,
                               final List<FlowDefinitionDto> flows, final List<OrgDto> organizations,
                               final List<ApplicationConfig> applications, final List<WebhookSubscriptionDto> webhooks,
                               final List<ScimTargetDto> scimTargets,
                               final List<WorkloadIdentityCredentialDto> workloadIdentity,
                               final List<MessagingProviderWriteDto> messagingProviders,
                               final List<MessageTemplateDto> messageTemplates, final List<AdminRoleGrantsDto> adminRoles,
                               final List<GroupDto> groups, final List<UserAdminDto> users,
                               final List<ProtocolMapperDto> clientProtocolMappers, final List<ClientRoleDto> clientRoles,
                               final List<ServiceAccountRoleDto> serviceAccountRoles,
                               final List<AllowedResourcesWrite> resourceIndicators,
                               final List<ClientAuthorizationDto> authorizationServices,
                               final List<io.helixiam.authorization.amqp.agent.AgentIdentityDto> agents,
                               final List<String> requiredEnv) {
        this(formatVersion, realm, clients, samlClients, roles, clientScopes, identityProviders, flows, organizations,
                applications, webhooks, scimTargets, workloadIdentity, messagingProviders, messageTemplates, adminRoles,
                groups, users, clientProtocolMappers, clientRoles, serviceAccountRoles, resourceIndicators,
                authorizationServices, agents, requiredEnv, null, null);
    }

    /** One organization's theme layer in an export, matched by organization name on import. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record OrganizationThemeExport(String organization,
                                          @com.fasterxml.jackson.databind.annotation.JsonDeserialize(
                                                  using = io.helixiam.authorization.theme.StrictThemeDeserializer.class)
                                          io.helixiam.authorization.theme.Theme theme) {
    }

    /** Back-compat constructor (the original 8 slices) — keeps existing call sites and v1 fixtures valid. */
    public RealmExportDocument(final Integer formatVersion, final RealmSettingsDto realm,
                               final List<ClientDto> clients, final List<SamlRelyingPartyConfig> samlClients,
                               final List<RoleDto> roles, final List<ScopeDetailDto> clientScopes,
                               final List<IdentityProviderConfig> identityProviders,
                               final List<FlowDefinitionDto> flows, final List<OrgDto> organizations) {
        this(formatVersion, realm, clients, samlClients, roles, clientScopes, identityProviders, flows,
                organizations, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
                null, null, null, null);
    }
}
