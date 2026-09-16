package group.mfnr.authorization.controller.admin.io;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import group.mfnr.authorization.amqp.adminrbac.AdminRoleGrantsDto;
import group.mfnr.authorization.amqp.application.ApplicationConfig;
import group.mfnr.authorization.amqp.client.ClientDto;
import group.mfnr.authorization.amqp.clientrole.ClientRoleDto;
import group.mfnr.authorization.amqp.clientrole.ServiceAccountRoleDto;
import group.mfnr.authorization.amqp.mapper.ProtocolMapperDto;
import group.mfnr.authorization.amqp.resource.AllowedResourcesWrite;
import group.mfnr.authorization.amqp.federation.IdentityProviderConfig;
import group.mfnr.authorization.amqp.flow.FlowDefinitionDto;
import group.mfnr.authorization.amqp.group.GroupDto;
import group.mfnr.authorization.amqp.messaging.MessageTemplateDto;
import group.mfnr.authorization.amqp.messaging.MessagingProviderWriteDto;
import group.mfnr.authorization.amqp.org.OrgDto;
import group.mfnr.authorization.amqp.realm.RealmSettingsDto;
import group.mfnr.authorization.amqp.role.RoleDto;
import group.mfnr.authorization.amqp.saml.SamlRelyingPartyConfig;
import group.mfnr.authorization.amqp.scim.ScimTargetDto;
import group.mfnr.authorization.amqp.scope.ScopeDetailDto;
import group.mfnr.authorization.amqp.user.UserAdminDto;
import group.mfnr.authorization.amqp.webhook.WebhookSubscriptionDto;
import group.mfnr.authorization.amqp.workloadidentity.WorkloadIdentityCredentialDto;

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
                                  List<group.mfnr.authorization.amqp.agent.AgentIdentityDto> agents,
                                  List<String> requiredEnv) {

    /**
     * The current document format version. v2 added the {@code requiredEnv} manifest, switched secret
     * masking from null-omission to {@code ${ENV_VAR}} placeholders, and grows additively with new config
     * slices (applications, webhooks, SCIM targets, workload identity, …); v1 documents still import.
     */
    public static final int CURRENT_FORMAT_VERSION = 2;

    /** Back-compat constructor (the original 8 slices) — keeps existing call sites and v1 fixtures valid. */
    public RealmExportDocument(final Integer formatVersion, final RealmSettingsDto realm,
                               final List<ClientDto> clients, final List<SamlRelyingPartyConfig> samlClients,
                               final List<RoleDto> roles, final List<ScopeDetailDto> clientScopes,
                               final List<IdentityProviderConfig> identityProviders,
                               final List<FlowDefinitionDto> flows, final List<OrgDto> organizations) {
        this(formatVersion, realm, clients, samlClients, roles, clientScopes, identityProviders, flows,
                organizations, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
                null, null);
    }
}
