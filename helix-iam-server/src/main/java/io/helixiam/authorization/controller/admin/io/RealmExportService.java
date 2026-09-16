package io.helixiam.authorization.controller.admin.io;

import io.helixiam.authorization.amqp.adminrbac.AdminRbacPublisher;
import io.helixiam.authorization.amqp.application.ApplicationConfigPublisher;
import io.helixiam.authorization.amqp.authz.AuthorizationPublisher;
import io.helixiam.authorization.amqp.authz.AuthzPermissionDto;
import io.helixiam.authorization.amqp.authz.AuthzPolicyDto;
import io.helixiam.authorization.amqp.authz.AuthzRef;
import io.helixiam.authorization.amqp.authz.AuthzResourceDto;
import io.helixiam.authorization.amqp.authz.AuthzScopeDto;
import io.helixiam.authorization.amqp.authz.AuthzServerDto;
import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.amqp.clientrole.ClientRoleDto;
import io.helixiam.authorization.amqp.clientrole.ClientRolePublisher;
import io.helixiam.authorization.amqp.clientrole.ClientRoleRef;
import io.helixiam.authorization.amqp.clientrole.ServiceAccountRoleDto;
import io.helixiam.authorization.amqp.mapper.ClientMapperPublisher;
import io.helixiam.authorization.amqp.mapper.MapperRef;
import io.helixiam.authorization.amqp.mapper.ProtocolMapperDto;
import io.helixiam.authorization.amqp.resource.AllowedResourcesWrite;
import io.helixiam.authorization.amqp.resource.ResourceIndicatorPublisher;
import io.helixiam.authorization.amqp.messaging.MessageTemplateDto;
import io.helixiam.authorization.amqp.messaging.MessagingAdminPublisher;
import io.helixiam.authorization.amqp.messaging.MessagingProviderDto;
import io.helixiam.authorization.amqp.messaging.MessagingProviderWriteDto;
import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfigPublisher;
import io.helixiam.authorization.amqp.scim.ScimTargetConfigPublisher;
import io.helixiam.authorization.amqp.scim.ScimTargetDto;
import io.helixiam.authorization.amqp.webhook.WebhookConfigPublisher;
import io.helixiam.authorization.amqp.webhook.WebhookSubscriptionDto;
import io.helixiam.authorization.amqp.workloadidentity.WorkloadIdentityConfigPublisher;
import io.helixiam.authorization.amqp.flow.FlowAdminPublisher;
import io.helixiam.authorization.amqp.flow.FlowDefinitionDto;
import io.helixiam.authorization.amqp.group.GroupAdminPublisher;
import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.flow.FlowRefDto;
import io.helixiam.authorization.amqp.flow.FlowSummaryDto;
import io.helixiam.authorization.amqp.org.OrganizationAdminPublisher;
import io.helixiam.authorization.amqp.realm.RealmAdminPublisher;
import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import io.helixiam.authorization.amqp.role.RoleAdminPublisher;
import io.helixiam.authorization.amqp.saml.SamlRelyingPartyConfigPublisher;
import io.helixiam.authorization.amqp.scope.ClaimScopePublisher;
import io.helixiam.authorization.amqp.scope.ClientScopeDto;
import io.helixiam.authorization.amqp.scope.ScopeDetailDto;
import io.helixiam.authorization.amqp.scope.ScopeRef;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Helix IAM: assembles a {@link RealmExportDocument} for one realm by composing the existing per-domain
 * admin publishers (no new AMQP exchange — this is a pure publisher-side orchestration). Every secret is
 * masked through {@link SecretMasking} before it leaves the building. Mirrors the controller-injection
 * style of the other admin endpoints (each domain reached through its own publisher seam).
 */
@Service
public class RealmExportService {

    private final RealmAdminPublisher realmPublisher;
    private final ClientAdminPublisher clientPublisher;
    private final SamlRelyingPartyConfigPublisher samlPublisher;
    private final RoleAdminPublisher rolePublisher;
    private final ClaimScopePublisher scopePublisher;
    private final IdentityProviderConfigPublisher idpPublisher;
    private final FlowAdminPublisher flowPublisher;
    private final OrganizationAdminPublisher orgPublisher;
    private final ApplicationConfigPublisher applicationPublisher;
    private final WebhookConfigPublisher webhookPublisher;
    private final ScimTargetConfigPublisher scimPublisher;
    private final WorkloadIdentityConfigPublisher workloadPublisher;
    private final MessagingAdminPublisher messagingPublisher;
    private final AdminRbacPublisher adminRbacPublisher;
    private final GroupAdminPublisher groupPublisher;
    private final UserAdminPublisher userPublisher;
    private final ClientMapperPublisher mapperPublisher;
    private final ClientRolePublisher clientRolePublisher;
    private final ResourceIndicatorPublisher resourcePublisher;
    private final AuthorizationPublisher authorizationPublisher;
    private final io.helixiam.authorization.amqp.agent.AgentIdentityPublisher agentPublisher;

    @Autowired
    public RealmExportService(final RealmAdminPublisher realmPublisher,
                              final ClientAdminPublisher clientPublisher,
                              final SamlRelyingPartyConfigPublisher samlPublisher,
                              final RoleAdminPublisher rolePublisher,
                              final ClaimScopePublisher scopePublisher,
                              final IdentityProviderConfigPublisher idpPublisher,
                              final FlowAdminPublisher flowPublisher,
                              final OrganizationAdminPublisher orgPublisher,
                              final ApplicationConfigPublisher applicationPublisher,
                              final WebhookConfigPublisher webhookPublisher,
                              final ScimTargetConfigPublisher scimPublisher,
                              final WorkloadIdentityConfigPublisher workloadPublisher,
                              final MessagingAdminPublisher messagingPublisher,
                              final AdminRbacPublisher adminRbacPublisher,
                              final GroupAdminPublisher groupPublisher,
                              final UserAdminPublisher userPublisher,
                              final ClientMapperPublisher mapperPublisher,
                              final ClientRolePublisher clientRolePublisher,
                              final ResourceIndicatorPublisher resourcePublisher,
                              final AuthorizationPublisher authorizationPublisher,
                              final io.helixiam.authorization.amqp.agent.AgentIdentityPublisher agentPublisher) {
        this.realmPublisher = realmPublisher;
        this.clientPublisher = clientPublisher;
        this.samlPublisher = samlPublisher;
        this.rolePublisher = rolePublisher;
        this.scopePublisher = scopePublisher;
        this.idpPublisher = idpPublisher;
        this.flowPublisher = flowPublisher;
        this.orgPublisher = orgPublisher;
        this.applicationPublisher = applicationPublisher;
        this.webhookPublisher = webhookPublisher;
        this.scimPublisher = scimPublisher;
        this.workloadPublisher = workloadPublisher;
        this.messagingPublisher = messagingPublisher;
        this.adminRbacPublisher = adminRbacPublisher;
        this.groupPublisher = groupPublisher;
        this.userPublisher = userPublisher;
        this.mapperPublisher = mapperPublisher;
        this.clientRolePublisher = clientRolePublisher;
        this.resourcePublisher = resourcePublisher;
        this.authorizationPublisher = authorizationPublisher;
        this.agentPublisher = agentPublisher;
    }

    /**
     * Reads every configurable slice of the realm and returns the export document. Secrets are emitted as
     * {@code ${ENV_VAR}} placeholders (v2) and the referenced var names are collected into
     * {@code requiredEnv} so an operator knows exactly what to set before importing elsewhere.
     */
    public RealmExportDocument export(final String realmId) {
        final java.util.Set<String> requiredEnv = new java.util.LinkedHashSet<>();

        // Client secrets are not in the read DTO (the subscriber owns/mints them); defensively null.
        final List<ClientDto> clients = nonNull(clientPublisher.list(realmId)).stream()
                .map(SecretMasking::mask).toList();

        final List<IdentityProviderConfig> idps = nonNull(idpPublisher.list(realmId)).stream()
                .map(idp -> SecretMasking.maskToPlaceholders(idp, requiredEnv)).toList();

        final RealmSettingsDto realm = SecretMasking.maskToPlaceholders(realmPublisher.get(realmId), requiredEnv);

        final List<WebhookSubscriptionDto> webhooks = nonNull(webhookPublisher.list(realmId)).stream()
                .map(w -> webhookWithPlaceholder(realmId, w, requiredEnv)).toList();
        final List<ScimTargetDto> scimTargets = nonNull(scimPublisher.list(realmId)).stream()
                .map(t -> scimWithPlaceholder(realmId, t, requiredEnv)).toList();
        final List<MessagingProviderWriteDto> messaging = nonNull(messagingPublisher.listProviders(realmId)).stream()
                .map(p -> messagingWithPlaceholder(realmId, p, requiredEnv)).toList();

        // Per-client config domains, flattened and keyed by the portable OAuth clientId string. Clients with
        // no Authorization-Services config are skipped so the list isn't full of empties.
        final List<ProtocolMapperDto> clientProtocolMappers = new ArrayList<>();
        final List<ClientRoleDto> clientRoles = new ArrayList<>();
        final List<ServiceAccountRoleDto> serviceAccountRoles = new ArrayList<>();
        final List<AllowedResourcesWrite> resourceIndicators = new ArrayList<>();
        final List<ClientAuthorizationDto> authorizationServices = new ArrayList<>();
        for (final ClientDto c : clients) {
            if (c == null || c.clientId() == null || c.clientId().isBlank()) {
                continue;
            }
            final String clientId = c.clientId();
            clientProtocolMappers.addAll(nonNull(mapperPublisher.list(new MapperRef(realmId, clientId, null))));
            clientRoles.addAll(nonNull(clientRolePublisher.listRoles(new ClientRoleRef(realmId, clientId, null))));
            serviceAccountRoles.addAll(nonNull(clientRolePublisher.serviceAccountRoles(
                    io.helixiam.authorization.support.RealmScopedKey.pack(realmId, clientId))));
            final List<String> allowed = nonNull(resourcePublisher.allowedResourcesForClient(
                    io.helixiam.authorization.support.RealmScopedKey.pack(realmId, clientId)));
            if (!allowed.isEmpty()) {
                resourceIndicators.add(new AllowedResourcesWrite(realmId, clientId, allowed));
            }
            final ClientAuthorizationDto authz = exportAuthorization(realmId, clientId);
            if (authz != null) {
                authorizationServices.add(authz);
            }
        }

        final List<String> required = requiredEnv.isEmpty() ? null : new ArrayList<>(requiredEnv);
        return new RealmExportDocument(
                RealmExportDocument.CURRENT_FORMAT_VERSION,
                realm,
                clients,
                nonNull(samlPublisher.list(realmId)),
                nonNull(rolePublisher.list(realmId)),
                exportScopes(realmId),
                idps,
                exportFlows(realmId),
                nonNull(orgPublisher.list(realmId)),
                nonNull(applicationPublisher.list(realmId)),
                webhooks,
                scimTargets,
                nonNull(workloadPublisher.list(realmId)),
                messaging,
                nonNull(messagingPublisher.listTemplates(realmId)),
                nonNull(adminRbacPublisher.roles(realmId)),
                nonNull(groupPublisher.list(realmId)),
                nonNull(userPublisher.list(realmId)),
                clientProtocolMappers,
                clientRoles,
                serviceAccountRoles,
                resourceIndicators,
                authorizationServices,
                nonNull(agentPublisher.list(realmId)),
                required);
    }

    /**
     * One client's UMA Authorization-Services config, or {@code null} when the client is not acting as a
     * resource server (server disabled and no scopes/resources/policies/permissions) — so the export omits it.
     */
    private ClientAuthorizationDto exportAuthorization(final String realmId, final String clientId) {
        final AuthzRef ref = new AuthzRef(realmId, clientId, null);
        final AuthzServerDto server = authorizationPublisher.getServer(ref);
        final List<AuthzScopeDto> scopes = nonNull(authorizationPublisher.listScopes(ref));
        final List<AuthzResourceDto> resources = nonNull(authorizationPublisher.listResources(ref));
        final List<AuthzPolicyDto> policies = nonNull(authorizationPublisher.listPolicies(ref));
        final List<AuthzPermissionDto> permissions = nonNull(authorizationPublisher.listPermissions(ref));
        final boolean enabled = server != null && Boolean.TRUE.equals(server.enabled());
        if (!enabled && scopes.isEmpty() && resources.isEmpty() && policies.isEmpty() && permissions.isEmpty()) {
            return null;
        }
        return new ClientAuthorizationDto(clientId, server, scopes, resources, policies, permissions);
    }

    /** Messaging provider → write DTO with its {@code secret} (and secret-looking config keys) as placeholders. */
    private static MessagingProviderWriteDto messagingWithPlaceholder(final String realmId,
                                                                      final MessagingProviderDto p,
                                                                      final java.util.Set<String> requiredEnv) {
        if (p == null) {
            return null;
        }
        final String channelDriver = p.channel() + "_" + p.driver();
        String secret = null;
        if (p.secretSet()) {
            final String name = SecretPlaceholders.nameFor(realmId, "messaging", channelDriver, "secret");
            requiredEnv.add(name);
            secret = "${" + name + "}";
        }
        java.util.Map<String, String> config = p.config();
        if (config != null && !config.isEmpty()) {
            final java.util.Map<String, String> masked = new java.util.LinkedHashMap<>();
            config.forEach((k, v) -> {
                if (SecretMasking.isSecretKey(k) && v != null && !v.isBlank()) {
                    final String name = SecretPlaceholders.nameFor(realmId, "messaging", channelDriver, k);
                    requiredEnv.add(name);
                    masked.put(k, "${" + name + "}");
                } else {
                    masked.put(k, v);
                }
            });
            config = masked;
        }
        return new MessagingProviderWriteDto(realmId, p.channel(), p.driver(), p.enabled(), p.fromAddress(),
                p.fromName(), config, secret);
    }

    /** Webhook HMAC secret → {@code ${ENV}} placeholder when the row has one ({@code secretSet}). */
    private static WebhookSubscriptionDto webhookWithPlaceholder(final String realmId,
                                                                 final WebhookSubscriptionDto w,
                                                                 final java.util.Set<String> requiredEnv) {
        if (w == null || !w.secretSet()) {
            return w;
        }
        final String name = SecretPlaceholders.nameFor(realmId, "webhook", w.name(), "secret");
        requiredEnv.add(name);
        return new WebhookSubscriptionDto(w.id(), w.realmId(), w.name(), w.url(), "${" + name + "}",
                w.secretSet(), w.eventTypes(), w.enabled(), w.createdAt());
    }

    /** SCIM bearer token → {@code ${ENV}} placeholder when the row has one ({@code tokenSet}). */
    private static ScimTargetDto scimWithPlaceholder(final String realmId, final ScimTargetDto t,
                                                     final java.util.Set<String> requiredEnv) {
        if (t == null || !t.tokenSet()) {
            return t;
        }
        final String name = SecretPlaceholders.nameFor(realmId, "scim", t.name(), "token");
        requiredEnv.add(name);
        return new ScimTargetDto(t.id(), t.realmId(), t.name(), t.baseUrl(), "${" + name + "}",
                t.tokenSet(), t.eventTypes(), t.enabled(), t.createdAt());
    }

    /** Each scope's full claim list (the list endpoint only carries a preview), via the scope-detail seam. */
    private List<ScopeDetailDto> exportScopes(final String realmId) {
        final List<ScopeDetailDto> out = new ArrayList<>();
        for (final ClientScopeDto summary : nonNull(scopePublisher.scopes(realmId))) {
            final ScopeDetailDto detail = scopePublisher.scope(new ScopeRef(realmId, summary.scopeId(), null));
            out.add(detail != null ? detail
                    : new ScopeDetailDto(realmId, summary.scopeId(), summary.name(), summary.description(), List.of()));
        }
        return out;
    }

    /** Every named flow with its full execution tree, via the per-alias detail seam. */
    private List<FlowDefinitionDto> exportFlows(final String realmId) {
        final List<FlowDefinitionDto> out = new ArrayList<>();
        for (final FlowSummaryDto summary : nonNull(flowPublisher.list(realmId))) {
            final FlowDefinitionDto def = flowPublisher.getByAlias(new FlowRefDto(realmId, summary.alias()));
            if (def != null) {
                out.add(def);
            }
        }
        return out;
    }

    private static <T> List<T> nonNull(final List<T> in) {
        return in == null ? List.of() : in;
    }
}
