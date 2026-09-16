package io.helixiam.authorization.controller.admin.io;

import io.helixiam.authorization.amqp.adminrbac.AdminRbacPublisher;
import io.helixiam.authorization.amqp.adminrbac.AdminRoleGrantWriteDto;
import io.helixiam.authorization.amqp.adminrbac.AdminRoleGrantsDto;
import io.helixiam.authorization.amqp.application.ApplicationConfig;
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
import io.helixiam.authorization.amqp.clientrole.ClientRoleWriteDto;
import io.helixiam.authorization.amqp.clientrole.ServiceAccountRoleDto;
import io.helixiam.authorization.amqp.mapper.ClientMapperPublisher;
import io.helixiam.authorization.amqp.mapper.MapperRef;
import io.helixiam.authorization.amqp.mapper.ProtocolMapperDto;
import io.helixiam.authorization.amqp.mapper.ProtocolMapperWriteDto;
import io.helixiam.authorization.amqp.resource.AllowedResourcesWrite;
import io.helixiam.authorization.amqp.resource.ResourceIndicatorPublisher;
import io.helixiam.authorization.amqp.messaging.MessageTemplateDto;
import io.helixiam.authorization.amqp.messaging.MessagingAdminPublisher;
import io.helixiam.authorization.amqp.messaging.MessagingProviderDto;
import io.helixiam.authorization.amqp.messaging.MessagingProviderWriteDto;
import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.amqp.client.ClientWriteDto;
import io.helixiam.authorization.amqp.scim.ScimTargetConfigPublisher;
import io.helixiam.authorization.amqp.scim.ScimTargetDto;
import io.helixiam.authorization.amqp.webhook.WebhookConfigPublisher;
import io.helixiam.authorization.amqp.webhook.WebhookSubscriptionDto;
import io.helixiam.authorization.amqp.workloadidentity.WorkloadIdentityConfigPublisher;
import io.helixiam.authorization.amqp.workloadidentity.WorkloadIdentityCredentialDto;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfigPublisher;
import io.helixiam.authorization.amqp.flow.FlowAdminPublisher;
import io.helixiam.authorization.amqp.flow.FlowCreateDto;
import io.helixiam.authorization.amqp.flow.FlowDefinitionDto;
import io.helixiam.authorization.amqp.flow.FlowSaveDto;
import io.helixiam.authorization.amqp.flow.FlowSummaryDto;
import io.helixiam.authorization.amqp.group.GroupAdminPublisher;
import io.helixiam.authorization.amqp.group.GroupDto;
import io.helixiam.authorization.amqp.group.GroupRef;
import io.helixiam.authorization.amqp.group.GroupWriteDto;
import io.helixiam.authorization.amqp.org.OrgDto;
import io.helixiam.authorization.amqp.org.OrgWriteDto;
import io.helixiam.authorization.amqp.org.OrganizationAdminPublisher;
import io.helixiam.authorization.amqp.realm.RealmAdminPublisher;
import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import io.helixiam.authorization.amqp.role.RoleAdminPublisher;
import io.helixiam.authorization.amqp.role.RoleAssignment;
import io.helixiam.authorization.amqp.role.RoleDto;
import io.helixiam.authorization.amqp.role.RoleRef;
import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserWriteDto;
import io.helixiam.authorization.amqp.saml.SamlRelyingPartyConfig;
import io.helixiam.authorization.amqp.saml.SamlRelyingPartyConfigPublisher;
import io.helixiam.authorization.amqp.scope.ClaimDto;
import io.helixiam.authorization.amqp.scope.ClaimScopePublisher;
import io.helixiam.authorization.amqp.scope.ClaimWriteDto;
import io.helixiam.authorization.amqp.scope.ClientScopeDto;
import io.helixiam.authorization.amqp.scope.ScopeDetailDto;
import io.helixiam.authorization.amqp.scope.ScopeRef;
import io.helixiam.authorization.amqp.scope.ScopeWriteDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM: idempotently upserts a {@link RealmExportDocument} into a target realm by composing the
 * existing per-domain admin publishers (no new AMQP exchange). Each slice is matched by its natural key
 * (client {@code clientId}, role {@code name}, scope {@code name}, claim {@code key}, SAML
 * {@code entityId}, IdP {@code alias}, org {@code name}); an existing entry is updated, a new one created.
 * Re-importing the same document a second time yields all-updates (no duplicates) — that invariant is the
 * core of the unit tests. Secrets are never written from the document (they were masked on export); a
 * client is (re)created without a secret, and the subscriber mints one as usual.
 *
 * <p>The {@code realmId} always comes from the request path (caller-supplied), never from the document —
 * so an export from realm {@code A} can be imported into realm {@code B}. Per the {@code /error}-redirect
 * gotcha, this service never throws on bad slice data: it counts the entry as {@code skipped} and moves on.
 */
@Service
public class RealmImportService {

    private static final org.apache.logging.log4j.Logger LOG =
            org.apache.logging.log4j.LogManager.getLogger(RealmImportService.class);

    /** Slice keys used in the result summary (also the JSON keys the console renders). */
    public static final String SLICE_REALM = "realm";
    public static final String SLICE_CLIENTS = "clients";
    public static final String SLICE_SAML = "samlClients";
    public static final String SLICE_ROLES = "roles";
    public static final String SLICE_SCOPES = "clientScopes";
    public static final String SLICE_IDPS = "identityProviders";
    public static final String SLICE_FLOWS = "flows";
    public static final String SLICE_ORGS = "organizations";
    public static final String SLICE_APPLICATIONS = "applications";
    public static final String SLICE_WEBHOOKS = "webhooks";
    public static final String SLICE_SCIM = "scimTargets";
    public static final String SLICE_WORKLOAD = "workloadIdentity";
    public static final String SLICE_MESSAGING = "messagingProviders";
    public static final String SLICE_TEMPLATES = "messageTemplates";
    public static final String SLICE_ADMIN_ROLES = "adminRoles";
    public static final String SLICE_GROUPS = "groups";
    public static final String SLICE_USERS = "users";
    public static final String SLICE_CLIENT_MAPPERS = "clientProtocolMappers";
    public static final String SLICE_CLIENT_ROLES = "clientRoles";
    public static final String SLICE_SA_ROLES = "serviceAccountRoles";
    public static final String SLICE_RESOURCE_INDICATORS = "resourceIndicators";
    public static final String SLICE_AUTHZ = "authorizationServices";
    public static final String SLICE_AGENTS = "agents";

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
    private final Environment environment;
    private final ClientMapperPublisher mapperPublisher;
    private final ClientRolePublisher clientRolePublisher;
    private final ResourceIndicatorPublisher resourcePublisher;
    private final AuthorizationPublisher authorizationPublisher;
    private final io.helixiam.authorization.amqp.agent.AgentIdentityPublisher agentPublisher;

    @Autowired
    public RealmImportService(final RealmAdminPublisher realmPublisher,
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
                              final Environment environment,
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
        this.environment = environment;
        this.mapperPublisher = mapperPublisher;
        this.clientRolePublisher = clientRolePublisher;
        this.resourcePublisher = resourcePublisher;
        this.authorizationPublisher = authorizationPublisher;
        this.agentPublisher = agentPublisher;
    }

    /** Resolves a {@code ${ENV_VAR}} secret placeholder against the environment, honouring the policy. */
    private String resolveSecret(final String value, final ImportOptions opts) {
        return SecretPlaceholders.resolve(value,
                environment == null ? k -> null : environment::getProperty,
                opts.missingSecretPolicy());
    }

    /** Resolves every {@code ${ENV_VAR}} placeholder in a config map (e.g. an IdP's secret entries). */
    private Map<String, String> resolveConfigSecrets(final Map<String, String> config, final ImportOptions opts) {
        if (config == null || config.isEmpty()) {
            return config;
        }
        final Map<String, String> out = new LinkedHashMap<>();
        config.forEach((k, v) -> out.put(k, resolveSecret(v, opts)));
        return out;
    }

    /** Upserts every present slice into {@code realmId} (overwrite mode); returns the per-slice summary. */
    public RealmImportResult importInto(final String realmId, final RealmExportDocument doc) {
        return importInto(realmId, doc, ImportOptions.OVERWRITE);
    }

    /** Applies every present slice into {@code realmId} honouring {@code options}; returns the summary. */
    public RealmImportResult importInto(final String realmId, final RealmExportDocument doc,
                                        final ImportOptions options) {
        final ImportOptions opts = options == null ? ImportOptions.OVERWRITE : options;
        final RealmImportResult.Builder result = new RealmImportResult.Builder(realmId);
        if (doc == null) {
            return result.build();
        }
        importRealm(realmId, doc, opts, result);
        importRoles(realmId, doc, opts, result);
        importScopes(realmId, doc, opts, result);
        importApplications(realmId, doc, opts, result);
        importClients(realmId, doc, opts, result);
        importSaml(realmId, doc, opts, result);
        importIdps(realmId, doc, opts, result);
        importFlows(realmId, doc, opts, result);
        importOrgs(realmId, doc, opts, result);
        importWebhooks(realmId, doc, opts, result);
        importScim(realmId, doc, opts, result);
        importWorkload(realmId, doc, opts, result);
        importMessaging(realmId, doc, opts, result);
        importTemplates(realmId, doc, opts, result);
        importAdminRoles(realmId, doc, opts, result);
        importGroups(realmId, doc, opts, result);
        importUsers(realmId, doc, opts, result);
        importClientProtocolMappers(realmId, doc, opts, result);
        importClientRoles(realmId, doc, opts, result);
        importResourceIndicators(realmId, doc, opts, result);
        importAuthorizationServices(realmId, doc, opts, result);
        importAgents(realmId, doc, opts, result);
        return result.build();
    }

    /**
     * The conflict gate. Returns {@code true} when an existing entry must NOT be written (it records the
     * {@code skipped}/{@code conflict} outcome itself). A non-existing entry is never blocked — it is
     * created. {@code OVERWRITE} never blocks; {@code SKIP} blocks silently; {@code FAIL} blocks + records.
     */
    private static boolean blocked(final boolean exists, final String slice, final String key,
                                   final ImportOptions opts, final RealmImportResult.Builder r) {
        if (!exists) {
            return false;
        }
        switch (opts.onConflict()) {
            case SKIP -> {
                r.skipped(slice);
                return true;
            }
            case FAIL -> {
                r.conflict(slice, key);
                r.skipped(slice);
                return true;
            }
            default -> {
                return false; // OVERWRITE
            }
        }
    }

    // --- realm settings: a single upsert; under SKIP/FAIL an already-configured realm is left untouched. ---
    private void importRealm(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                             final RealmImportResult.Builder r) {
        final RealmSettingsDto in = doc.realm();
        if (in == null) {
            return;
        }
        final boolean exists;
        try {
            exists = realmPublisher.get(realmId) != null;
        } catch (final RuntimeException ex) {
            r.skipped(SLICE_REALM);
            return;
        }
        if (blocked(exists, SLICE_REALM, realmId, opts, r)) {
            return;
        }
        try {
            // Force the target realm id from the path; never carry the source realm's CAPTCHA secret.
            final RealmSettingsDto retargeted = new RealmSettingsDto(realmId, in.displayName(), in.issuer(),
                    in.accessTokenTtlSeconds(), in.refreshTokenTtlSeconds(), in.reuseRefreshTokens(), in.requireMfa(),
                    in.passwordMinLength(), in.enabled(), in.ssoSessionIdleTimeoutSeconds(),
                    in.ssoSessionMaxLifetimeSeconds(), in.rememberMe(), in.rememberMeLifetimeSeconds(),
                    in.lockoutEnabled(), in.maxLoginFailures(), in.lockoutDurationSeconds(), in.failureResetSeconds(),
                    in.permanentLockout(), in.passwordRequireUppercase(), in.passwordRequireLowercase(),
                    in.passwordRequireDigit(), in.passwordRequireSpecial(), in.passwordNotUsername(),
                    in.passwordHistoryCount(), in.breachedPasswordCheck(), in.captchaProvider(), in.captchaSiteKey(),
                    resolveSecret(in.captchaSecretKey(), opts), in.maxConcurrentSessions(),
                    in.concurrentSessionEvictOldest(), in.riskPolicyEnabled(),
                    in.riskMediumThreshold(), in.riskHighThreshold(), in.riskLowAction(), in.riskMediumAction(),
                    in.riskHighAction(),
                    in.logoUrl(), in.primaryColor(), in.backgroundColor(), in.welcomeText(), in.customCss(),
                    in.registrationEnabled());
            realmPublisher.save(retargeted);
            if (exists) {
                r.updated(SLICE_REALM);
            } else {
                r.created(SLICE_REALM);
            }
        } catch (final RuntimeException ex) {
            r.skipped(SLICE_REALM);
        }
    }

    // --- roles: create by name; if the name already exists, count as updated (or skip per conflict mode). ---
    private void importRoles(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                             final RealmImportResult.Builder r) {
        if (doc.roles() == null) {
            return;
        }
        final Map<String, RoleDto> existing = byKey(rolePublisher.list(realmId), RoleDto::name);
        for (final RoleDto role : doc.roles()) {
            if (role == null || isBlank(role.name())) {
                r.skipped(SLICE_ROLES);
                continue;
            }
            final boolean exists = existing.containsKey(role.name());
            if (blocked(exists, SLICE_ROLES, role.name(), opts, r)) {
                continue;
            }
            try {
                if (exists) {
                    r.updated(SLICE_ROLES); // create is idempotent on name (no-op when present)
                } else {
                    rolePublisher.create(new RoleRef(realmId, null, role.name()));
                    r.created(SLICE_ROLES);
                }
            } catch (final RuntimeException ex) {
                r.skipped(SLICE_ROLES);
            }
        }
    }

    // --- client scopes + their claim catalogue: upsert claims by key, scopes by name, then map. ---
    private void importScopes(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                              final RealmImportResult.Builder r) {
        if (doc.clientScopes() == null) {
            return;
        }
        // First make sure every claim referenced by any imported scope exists in the realm catalogue.
        final Map<String, ClaimDto> claimsByKey = byKey(scopePublisher.claims(realmId), ClaimDto::key);
        for (final ScopeDetailDto scope : doc.clientScopes()) {
            if (scope == null) {
                continue;
            }
            for (final ClaimDto claim : nonNull(scope.claims())) {
                if (claim == null || isBlank(claim.key()) || claimsByKey.containsKey(claim.key())) {
                    continue;
                }
                try {
                    final ClaimDto created = scopePublisher.createClaim(new ClaimWriteDto(realmId, null, claim.key(),
                            claim.label(), claim.placeholder(), claim.mandatory()));
                    if (created != null) {
                        claimsByKey.put(created.key(), created);
                    }
                } catch (final RuntimeException ignored) {
                    // a claim that can't be created just won't be mappable below; not fatal.
                }
            }
        }

        final Map<String, ClientScopeDto> existingScopes = byKey(scopePublisher.scopes(realmId), ClientScopeDto::name);
        for (final ScopeDetailDto scope : doc.clientScopes()) {
            if (scope == null || isBlank(scope.name())) {
                r.skipped(SLICE_SCOPES);
                continue;
            }
            if (blocked(existingScopes.containsKey(scope.name()), SLICE_SCOPES, scope.name(), opts, r)) {
                continue;
            }
            try {
                final String scopeId;
                if (existingScopes.containsKey(scope.name())) {
                    scopeId = existingScopes.get(scope.name()).scopeId();
                    r.updated(SLICE_SCOPES);
                } else {
                    final ClientScopeDto created = scopePublisher.createScope(
                            new ScopeWriteDto(realmId, scope.name(), scope.description()));
                    scopeId = created == null ? null : created.scopeId();
                    r.created(SLICE_SCOPES);
                }
                if (scopeId != null) {
                    for (final ClaimDto claim : nonNull(scope.claims())) {
                        final ClaimDto target = claim == null ? null : claimsByKey.get(claim.key());
                        if (target != null) {
                            scopePublisher.addClaim(new ScopeRef(realmId, scopeId, target.claimId()));
                        }
                    }
                }
            } catch (final RuntimeException ex) {
                r.skipped(SLICE_SCOPES);
            }
        }
    }

    // --- OIDC clients: match by clientId; update keeps the existing id, secret never written. ---
    private void importClients(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                               final RealmImportResult.Builder r) {
        if (doc.clients() == null) {
            return;
        }
        final Map<String, ClientDto> existing = byKey(clientPublisher.list(realmId), ClientDto::clientId);
        for (final ClientDto c : doc.clients()) {
            if (c == null || isBlank(c.clientId())) {
                r.skipped(SLICE_CLIENTS);
                continue;
            }
            if (blocked(existing.containsKey(c.clientId()), SLICE_CLIENTS, c.clientId(), opts, r)) {
                continue;
            }
            try {
                final ClientDto current = existing.get(c.clientId());
                final String id = current == null ? null : current.id();
                final ClientWriteDto write = new ClientWriteDto(realmId, id, c.clientId(), c.grantTypes(),
                        c.redirectUris(), c.scopes(), c.subjectClaim(), c.authFlowAlias(), c.name(), c.description(),
                        c.postLogoutRedirectUris(), c.webOrigins(), c.publicClient(), c.consentRequired(),
                        c.displayOnConsentScreen(), c.loginTheme(), c.rootUrl(), c.homeUrl(), c.adminUrl(),
                        c.alwaysDisplayInConsole(), c.accessTokenLifespan(), c.refreshTokenLifespan(),
                        c.idTokenSignatureAlg(), c.reuseRefreshTokens(), c.tokenEndpointAuthMethod(), c.jwksUrl(),
                        c.backchannelLogoutUri(), c.frontchannelLogoutUri(), c.applicationId(),
                        c.x509CertificateBoundAccessTokens(), c.requireSignedRequestObject(), c.jarmResponseMode());
                if (current == null) {
                    clientPublisher.create(write);
                    r.created(SLICE_CLIENTS);
                } else {
                    clientPublisher.update(write);
                    r.updated(SLICE_CLIENTS);
                }
            } catch (final RuntimeException ex) {
                r.skipped(SLICE_CLIENTS);
            }
        }
    }

    // --- SAML relying parties: save is upsert by entityId; create/update decided by existing list. ---
    private void importSaml(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                            final RealmImportResult.Builder r) {
        if (doc.samlClients() == null) {
            return;
        }
        final Map<String, SamlRelyingPartyConfig> existing = byKey(samlPublisher.list(realmId),
                SamlRelyingPartyConfig::entityId);
        for (final SamlRelyingPartyConfig sp : doc.samlClients()) {
            if (sp == null || isBlank(sp.entityId())) {
                r.skipped(SLICE_SAML);
                continue;
            }
            if (blocked(existing.containsKey(sp.entityId()), SLICE_SAML, sp.entityId(), opts, r)) {
                continue;
            }
            try {
                final boolean update = existing.containsKey(sp.entityId());
                samlPublisher.save(new SamlRelyingPartyConfig(realmId, sp.entityId(), sp.assertionConsumerServiceUrl(),
                        sp.defaultAuthnContextClassRef(), sp.singleLogoutServiceUrl(), sp.signingCertificate(),
                        sp.enabled(), sp.applicationId(), sp.options()));
                if (update) {
                    r.updated(SLICE_SAML);
                } else {
                    r.created(SLICE_SAML);
                }
            } catch (final RuntimeException ex) {
                r.skipped(SLICE_SAML);
            }
        }
    }

    // --- identity providers: save is upsert by alias; secret config entries are absent (masked on export). ---
    private void importIdps(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                            final RealmImportResult.Builder r) {
        if (doc.identityProviders() == null) {
            return;
        }
        final Map<String, IdentityProviderConfig> existing = byKey(idpPublisher.list(realmId),
                IdentityProviderConfig::alias);
        for (final IdentityProviderConfig idp : doc.identityProviders()) {
            if (idp == null || isBlank(idp.alias())) {
                r.skipped(SLICE_IDPS);
                continue;
            }
            if (blocked(existing.containsKey(idp.alias()), SLICE_IDPS, idp.alias(), opts, r)) {
                continue;
            }
            try {
                final boolean update = existing.containsKey(idp.alias());
                idpPublisher.save(new IdentityProviderConfig(realmId, idp.alias(), idp.protocol(),
                        idp.displayName(), idp.enabled(), resolveConfigSecrets(idp.config(), opts)));
                if (update) {
                    r.updated(SLICE_IDPS);
                } else {
                    r.created(SLICE_IDPS);
                }
            } catch (final RuntimeException ex) {
                r.skipped(SLICE_IDPS);
            }
        }
    }

    // --- auth flows: create the flow if its alias is new, then save its full execution tree. ---
    private void importFlows(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                             final RealmImportResult.Builder r) {
        if (doc.flows() == null) {
            return;
        }
        final Map<String, FlowSummaryDto> existing = byKey(flowPublisher.list(realmId), FlowSummaryDto::alias);
        for (final FlowDefinitionDto flow : doc.flows()) {
            if (flow == null || isBlank(flow.alias())) {
                r.skipped(SLICE_FLOWS);
                continue;
            }
            if (blocked(existing.containsKey(flow.alias()), SLICE_FLOWS, flow.alias(), opts, r)) {
                continue;
            }
            try {
                final boolean update = existing.containsKey(flow.alias());
                if (!update) {
                    flowPublisher.create(new FlowCreateDto(realmId, flow.alias(), null));
                }
                flowPublisher.save(new FlowSaveDto(realmId, flow.alias(), flow.executions()));
                if (update) {
                    r.updated(SLICE_FLOWS);
                } else {
                    r.created(SLICE_FLOWS);
                }
            } catch (final RuntimeException ex) {
                r.skipped(SLICE_FLOWS);
            }
        }
    }

    // --- organizations: match by name; update keeps the existing orgId. ---
    private void importOrgs(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                            final RealmImportResult.Builder r) {
        if (doc.organizations() == null) {
            return;
        }
        final Map<String, OrgDto> existing = byKey(orgPublisher.list(realmId), OrgDto::name);
        for (final OrgDto org : doc.organizations()) {
            if (org == null || isBlank(org.name())) {
                r.skipped(SLICE_ORGS);
                continue;
            }
            if (blocked(existing.containsKey(org.name()), SLICE_ORGS, org.name(), opts, r)) {
                continue;
            }
            try {
                final OrgDto current = existing.get(org.name());
                if (current == null) {
                    orgPublisher.create(new OrgWriteDto(realmId, null, org.name(), org.displayName(),
                            org.domains(), org.enabled()));
                    r.created(SLICE_ORGS);
                } else {
                    orgPublisher.update(new OrgWriteDto(realmId, current.orgId(), org.name(), org.displayName(),
                            org.domains(), org.enabled()));
                    r.updated(SLICE_ORGS);
                }
            } catch (final RuntimeException ex) {
                r.skipped(SLICE_ORGS);
            }
        }
    }

    // --- applications (WSO2-style parent): save is upsert by name. ---
    private void importApplications(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                                    final RealmImportResult.Builder r) {
        if (doc.applications() == null) {
            return;
        }
        final Map<String, ApplicationConfig> existing = byKey(applicationPublisher.list(realmId), ApplicationConfig::name);
        for (final ApplicationConfig app : doc.applications()) {
            if (app == null || isBlank(app.name())) {
                r.skipped(SLICE_APPLICATIONS);
                continue;
            }
            final boolean exists = existing.containsKey(app.name());
            if (blocked(exists, SLICE_APPLICATIONS, app.name(), opts, r)) {
                continue;
            }
            try {
                applicationPublisher.save(new ApplicationConfig(realmId, app.name(), app.description(),
                        app.subjectClaim(), app.authFlowAlias(), app.enabled(), app.displayName()));
                if (exists) {
                    r.updated(SLICE_APPLICATIONS);
                } else {
                    r.created(SLICE_APPLICATIONS);
                }
            } catch (final RuntimeException ex) {
                r.skipped(SLICE_APPLICATIONS);
            }
        }
    }

    // --- outbound webhooks: match by name; keep the existing id on update; HMAC secret resolved from env. ---
    /**
     * Agent (NHI) registry slice: idempotent upsert by the realm-unique agent {@code name}. Profiles +
     * lifecycle + bound client are carried; no secret crosses the wire (agents authenticate via their
     * bound client / WIF). A re-home keeps the target realm id and re-resolves the existing agent by name.
     */
    private void importAgents(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                              final RealmImportResult.Builder r) {
        if (doc.agents() == null) {
            return;
        }
        final Map<String, io.helixiam.authorization.amqp.agent.AgentIdentityDto> existing =
                byKey(agentPublisher.list(realmId), io.helixiam.authorization.amqp.agent.AgentIdentityDto::name);
        for (final io.helixiam.authorization.amqp.agent.AgentIdentityDto a : doc.agents()) {
            if (a == null || isBlank(a.name())) {
                r.skipped(SLICE_AGENTS);
                continue;
            }
            final io.helixiam.authorization.amqp.agent.AgentIdentityDto current = existing.get(a.name());
            if (blocked(current != null, SLICE_AGENTS, a.name(), opts, r)) {
                continue;
            }
            try {
                agentPublisher.save(new io.helixiam.authorization.amqp.agent.AgentIdentityDto(
                        current == null ? null : current.id(), realmId, a.name(), a.displayName(), a.description(),
                        a.owner(), a.status(), a.authMethod(), a.clientId(), a.scopes(), a.enabled(),
                        a.createdAt(), a.expiresAt(), a.lastUsedAt(), a.roles()));
                if (current == null) {
                    r.created(SLICE_AGENTS);
                } else {
                    r.updated(SLICE_AGENTS);
                }
            } catch (final RuntimeException ex) {
                LOG.warn("Helix realm import [{}]: skipped agent '{}': {}", realmId, a.name(), ex.toString());
                r.skipped(SLICE_AGENTS);
            }
        }
    }

    private void importWebhooks(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                                final RealmImportResult.Builder r) {
        if (doc.webhooks() == null) {
            return;
        }
        final Map<String, WebhookSubscriptionDto> existing = byKey(webhookPublisher.list(realmId),
                WebhookSubscriptionDto::name);
        for (final WebhookSubscriptionDto w : doc.webhooks()) {
            if (w == null || isBlank(w.name())) {
                r.skipped(SLICE_WEBHOOKS);
                continue;
            }
            final WebhookSubscriptionDto current = existing.get(w.name());
            if (blocked(current != null, SLICE_WEBHOOKS, w.name(), opts, r)) {
                continue;
            }
            try {
                final String secret = resolveSecret(w.secret(), opts);
                webhookPublisher.save(new WebhookSubscriptionDto(current == null ? null : current.id(), realmId,
                        w.name(), w.url(), secret, secret != null, w.eventTypes(), w.enabled(), w.createdAt()));
                if (current == null) {
                    r.created(SLICE_WEBHOOKS);
                } else {
                    r.updated(SLICE_WEBHOOKS);
                }
            } catch (final RuntimeException ex) {
                r.skipped(SLICE_WEBHOOKS);
            }
        }
    }

    // --- outbound SCIM targets: match by name; bearer token resolved from env. ---
    private void importScim(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                            final RealmImportResult.Builder r) {
        if (doc.scimTargets() == null) {
            return;
        }
        final Map<String, ScimTargetDto> existing = byKey(scimPublisher.list(realmId), ScimTargetDto::name);
        for (final ScimTargetDto t : doc.scimTargets()) {
            if (t == null || isBlank(t.name())) {
                r.skipped(SLICE_SCIM);
                continue;
            }
            final ScimTargetDto current = existing.get(t.name());
            if (blocked(current != null, SLICE_SCIM, t.name(), opts, r)) {
                continue;
            }
            try {
                final String token = resolveSecret(t.token(), opts);
                scimPublisher.save(new ScimTargetDto(current == null ? null : current.id(), realmId, t.name(),
                        t.baseUrl(), token, token != null, t.eventTypes(), t.enabled(), t.createdAt()));
                if (current == null) {
                    r.created(SLICE_SCIM);
                } else {
                    r.updated(SLICE_SCIM);
                }
            } catch (final RuntimeException ex) {
                r.skipped(SLICE_SCIM);
            }
        }
    }

    // --- workload-identity credentials: match by name; no secret (inbound JWKS trust anchor). ---
    private void importWorkload(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                                final RealmImportResult.Builder r) {
        if (doc.workloadIdentity() == null) {
            return;
        }
        final Map<String, WorkloadIdentityCredentialDto> existing = byKey(workloadPublisher.list(realmId),
                WorkloadIdentityCredentialDto::name);
        for (final WorkloadIdentityCredentialDto w : doc.workloadIdentity()) {
            if (w == null || isBlank(w.name())) {
                r.skipped(SLICE_WORKLOAD);
                continue;
            }
            final WorkloadIdentityCredentialDto current = existing.get(w.name());
            if (blocked(current != null, SLICE_WORKLOAD, w.name(), opts, r)) {
                continue;
            }
            try {
                workloadPublisher.save(new WorkloadIdentityCredentialDto(current == null ? null : current.id(),
                        realmId, w.name(), w.issuer(), w.jwksUri(), w.subject(), w.audience(), w.clientId(),
                        w.scopes(), w.enabled(), w.createdAt()));
                if (current == null) {
                    r.created(SLICE_WORKLOAD);
                } else {
                    r.updated(SLICE_WORKLOAD);
                }
            } catch (final RuntimeException ex) {
                r.skipped(SLICE_WORKLOAD);
            }
        }
    }

    // --- messaging providers: match by channel+driver; provider secret + secret-looking config resolved from env. ---
    private void importMessaging(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                                 final RealmImportResult.Builder r) {
        if (doc.messagingProviders() == null) {
            return;
        }
        final Map<String, MessagingProviderDto> existing = byKey(messagingPublisher.listProviders(realmId),
                p -> p.channel() + "_" + p.driver());
        for (final MessagingProviderWriteDto p : doc.messagingProviders()) {
            if (p == null || isBlank(p.channel()) || isBlank(p.driver())) {
                r.skipped(SLICE_MESSAGING);
                continue;
            }
            final String key = p.channel() + "_" + p.driver();
            if (blocked(existing.containsKey(key), SLICE_MESSAGING, key, opts, r)) {
                continue;
            }
            try {
                messagingPublisher.saveProvider(new MessagingProviderWriteDto(realmId, p.channel(), p.driver(),
                        p.enabled(), p.fromAddress(), p.fromName(), resolveConfigSecrets(p.config(), opts),
                        resolveSecret(p.secret(), opts)));
                if (existing.containsKey(key)) {
                    r.updated(SLICE_MESSAGING);
                } else {
                    r.created(SLICE_MESSAGING);
                }
            } catch (final RuntimeException ex) {
                r.skipped(SLICE_MESSAGING);
            }
        }
    }

    // --- message templates: match by templateKey+channel; keep the existing id on update; no secrets. ---
    private void importTemplates(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                                 final RealmImportResult.Builder r) {
        if (doc.messageTemplates() == null) {
            return;
        }
        final Map<String, MessageTemplateDto> existing = byKey(messagingPublisher.listTemplates(realmId),
                t -> t.templateKey() + "_" + t.channel());
        for (final MessageTemplateDto t : doc.messageTemplates()) {
            if (t == null || isBlank(t.templateKey())) {
                r.skipped(SLICE_TEMPLATES);
                continue;
            }
            final MessageTemplateDto current = existing.get(t.templateKey() + "_" + t.channel());
            if (blocked(current != null, SLICE_TEMPLATES, t.templateKey() + "_" + t.channel(), opts, r)) {
                continue;
            }
            try {
                messagingPublisher.saveTemplate(new MessageTemplateDto(current == null ? null : current.id(), realmId,
                        t.templateKey(), t.channel(), t.subject(), t.body(), t.enabled(), t.html()));
                if (current == null) {
                    r.created(SLICE_TEMPLATES);
                } else {
                    r.updated(SLICE_TEMPLATES);
                }
            } catch (final RuntimeException ex) {
                r.skipped(SLICE_TEMPLATES);
            }
        }
    }

    // --- admin RBAC: re-target each role-grant by role NAME to the target realm's role id, then set. ---
    private void importAdminRoles(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                                  final RealmImportResult.Builder r) {
        if (doc.adminRoles() == null) {
            return;
        }
        final Map<String, RoleDto> roleByName = byKey(rolePublisher.list(realmId), RoleDto::name);
        final Map<String, AdminRoleGrantsDto> existing = byKey(adminRbacPublisher.roles(realmId),
                AdminRoleGrantsDto::roleName);
        for (final AdminRoleGrantsDto grant : doc.adminRoles()) {
            if (grant == null || isBlank(grant.roleName())) {
                r.skipped(SLICE_ADMIN_ROLES);
                continue;
            }
            final RoleDto targetRole = roleByName.get(grant.roleName());
            if (targetRole == null) {
                r.skipped(SLICE_ADMIN_ROLES); // the realm role does not exist in the target — nothing to grant onto
                continue;
            }
            if (blocked(existing.containsKey(grant.roleName()), SLICE_ADMIN_ROLES, grant.roleName(), opts, r)) {
                continue;
            }
            try {
                adminRbacPublisher.set(new AdminRoleGrantWriteDto(realmId, targetRole.roleId(), grant.permissions()));
                if (existing.containsKey(grant.roleName())) {
                    r.updated(SLICE_ADMIN_ROLES);
                } else {
                    r.created(SLICE_ADMIN_ROLES);
                }
            } catch (final RuntimeException ex) {
                r.skipped(SLICE_ADMIN_ROLES);
            }
        }
    }

    // --- groups: re-create the hierarchy parent-before-child by NAME, then re-map role assignments. ---
    private void importGroups(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                              final RealmImportResult.Builder r) {
        if (doc.groups() == null) {
            return;
        }
        final Map<String, GroupDto> existing = byKey(groupPublisher.list(realmId), GroupDto::name);
        final Map<String, RoleDto> roleByName = byKey(rolePublisher.list(realmId), RoleDto::name);
        // The document's parentId is a SOURCE group id; map it back to a name, then to the target id.
        final Map<String, String> sourceIdToName = new LinkedHashMap<>();
        for (final GroupDto g : doc.groups()) {
            if (g != null && g.groupId() != null && !isBlank(g.name())) {
                sourceIdToName.put(g.groupId(), g.name());
            }
        }
        final Map<String, String> nameToTargetId = new LinkedHashMap<>();
        existing.forEach((name, g) -> nameToTargetId.put(name, g.groupId()));

        final List<GroupDto> pending = new java.util.ArrayList<>(doc.groups());
        boolean progressed = true;
        while (!pending.isEmpty() && progressed) {
            progressed = false;
            final java.util.Iterator<GroupDto> it = pending.iterator();
            while (it.hasNext()) {
                final GroupDto g = it.next();
                if (g == null || isBlank(g.name())) {
                    r.skipped(SLICE_GROUPS);
                    it.remove();
                    progressed = true;
                    continue;
                }
                final String parentName = g.parentId() == null ? null : sourceIdToName.get(g.parentId());
                final String parentTargetId = parentName == null ? null : nameToTargetId.get(parentName);
                if (g.parentId() != null && parentTargetId == null) {
                    continue; // parent not created yet — try again on a later pass
                }
                it.remove();
                progressed = true;
                final boolean exists = existing.containsKey(g.name());
                if (blocked(exists, SLICE_GROUPS, g.name(), opts, r)) {
                    continue;
                }
                try {
                    final String targetId;
                    if (exists) {
                        targetId = existing.get(g.name()).groupId();
                        groupPublisher.update(new GroupWriteDto(realmId, targetId, g.name(), parentTargetId));
                        r.updated(SLICE_GROUPS);
                    } else {
                        final GroupDto created = groupPublisher.create(
                                new GroupWriteDto(realmId, null, g.name(), parentTargetId));
                        targetId = created == null ? null : created.groupId();
                        r.created(SLICE_GROUPS);
                    }
                    if (targetId != null) {
                        nameToTargetId.put(g.name(), targetId);
                        for (final String roleName : nonNull(g.roleNames())) {
                            final RoleDto role = roleByName.get(roleName);
                            if (role != null) {
                                groupPublisher.assignRole(new GroupRef(realmId, targetId, null, role.roleId()));
                            }
                        }
                    }
                } catch (final RuntimeException ex) {
                    LOG.warn("Helix realm import [{}]: skipped group '{}': {}", realmId, g.name(), ex.toString());
                    r.skipped(SLICE_GROUPS);
                }
            }
        }
        for (final GroupDto orphan : pending) { // unreachable parents / cycles
            if (orphan != null) {
                r.skipped(SLICE_GROUPS);
            }
        }
    }

    // --- users (profiles + role assignments, no credentials): match by username; assign realm roles by name. ---
    private void importUsers(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                             final RealmImportResult.Builder r) {
        if (doc.users() == null) {
            return;
        }
        final Map<String, UserAdminDto> existing = byKey(userPublisher.list(realmId), UserAdminDto::username);
        final Map<String, RoleDto> roleByName = byKey(rolePublisher.list(realmId), RoleDto::name);
        for (final UserAdminDto u : doc.users()) {
            if (u == null || isBlank(u.username())) {
                r.skipped(SLICE_USERS);
                continue;
            }
            final UserAdminDto current = existing.get(u.username());
            if (blocked(current != null, SLICE_USERS, u.username(), opts, r)) {
                continue;
            }
            try {
                // No password / MFA secret is ever written — profile + flags + attributes only.
                final UserWriteDto write = new UserWriteDto(realmId, current == null ? null : current.userId(),
                        u.username(), u.email(), null, u.enabled(), u.locked(), u.attributes());
                final UserAdminDto saved = current == null ? userPublisher.create(write) : userPublisher.update(write);
                final String userId = saved != null ? saved.userId() : (current == null ? null : current.userId());
                if (current == null) {
                    r.created(SLICE_USERS);
                } else {
                    r.updated(SLICE_USERS);
                }
                if (userId != null) {
                    for (final String roleName : nonNull(u.roles())) {
                        final RoleDto role = roleByName.get(roleName);
                        if (role != null) {
                            rolePublisher.assign(new RoleAssignment(realmId, userId, role.roleId()));
                        }
                    }
                }
            } catch (final RuntimeException ex) {
                LOG.warn("Helix realm import [{}]: skipped user '{}': {}", realmId, u.username(), ex.toString());
                r.skipped(SLICE_USERS);
            }
        }
    }

    // --- per-client protocol mappers: match by clientId+name; upsert (create new, update existing by id). ---
    private void importClientProtocolMappers(final String realmId, final RealmExportDocument doc,
                                             final ImportOptions opts, final RealmImportResult.Builder r) {
        if (doc.clientProtocolMappers() == null) {
            return;
        }
        final Map<String, ClientDto> targets = byKey(clientPublisher.list(realmId), ClientDto::clientId);
        for (final ProtocolMapperDto m : doc.clientProtocolMappers()) {
            if (m == null || isBlank(m.clientId()) || isBlank(m.name())) {
                r.skipped(SLICE_CLIENT_MAPPERS);
                continue;
            }
            if (!targets.containsKey(m.clientId())) {
                LOG.warn("Helix realm import [{}]: skipped protocol mapper '{}' — client '{}' not in target realm",
                        realmId, m.name(), m.clientId());
                r.skipped(SLICE_CLIENT_MAPPERS);
                continue;
            }
            final Map<String, ProtocolMapperDto> existing = byKey(
                    mapperPublisher.list(new MapperRef(realmId, m.clientId(), null)), ProtocolMapperDto::name);
            final ProtocolMapperDto current = existing.get(m.name());
            if (blocked(current != null, SLICE_CLIENT_MAPPERS, m.clientId() + ":" + m.name(), opts, r)) {
                continue;
            }
            try {
                final ProtocolMapperWriteDto write = new ProtocolMapperWriteDto(
                        current == null ? null : current.mapperId(), realmId, m.clientId(), m.name(), m.mapperType(),
                        m.source(), m.claimName(), m.addToAccessToken(), m.addToIdToken());
                if (current == null) {
                    mapperPublisher.create(write);
                    r.created(SLICE_CLIENT_MAPPERS);
                } else {
                    mapperPublisher.update(write);
                    r.updated(SLICE_CLIENT_MAPPERS);
                }
            } catch (final RuntimeException ex) {
                LOG.warn("Helix realm import [{}]: skipped protocol mapper '{}' on '{}': {}", realmId, m.name(),
                        m.clientId(), ex.toString());
                r.skipped(SLICE_CLIENT_MAPPERS);
            }
        }
    }

    // --- client roles + service-account role grants: match by clientId+name; both create idempotently by name. ---
    private void importClientRoles(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                                   final RealmImportResult.Builder r) {
        final Map<String, ClientDto> targets = byKey(clientPublisher.list(realmId), ClientDto::clientId);
        if (doc.clientRoles() != null) {
            for (final ClientRoleDto role : doc.clientRoles()) {
                if (role == null || isBlank(role.clientId()) || isBlank(role.name())) {
                    r.skipped(SLICE_CLIENT_ROLES);
                    continue;
                }
                if (!targets.containsKey(role.clientId())) {
                    LOG.warn("Helix realm import [{}]: skipped client role '{}' — client '{}' not in target realm",
                            realmId, role.name(), role.clientId());
                    r.skipped(SLICE_CLIENT_ROLES);
                    continue;
                }
                final Map<String, ClientRoleDto> existing = byKey(
                        clientRolePublisher.listRoles(new ClientRoleRef(realmId, role.clientId(), null)),
                        ClientRoleDto::name);
                final boolean exists = existing.containsKey(role.name());
                if (blocked(exists, SLICE_CLIENT_ROLES, role.clientId() + ":" + role.name(), opts, r)) {
                    continue;
                }
                try {
                    if (exists) {
                        r.updated(SLICE_CLIENT_ROLES); // createRole is idempotent on name (no-op when present)
                    } else {
                        clientRolePublisher.createRole(
                                new ClientRoleWriteDto(realmId, role.clientId(), role.name(), role.description()));
                        r.created(SLICE_CLIENT_ROLES);
                    }
                } catch (final RuntimeException ex) {
                    LOG.warn("Helix realm import [{}]: skipped client role '{}' on '{}': {}", realmId, role.name(),
                            role.clientId(), ex.toString());
                    r.skipped(SLICE_CLIENT_ROLES);
                }
            }
        }
        if (doc.serviceAccountRoles() != null) {
            for (final ServiceAccountRoleDto sa : doc.serviceAccountRoles()) {
                if (sa == null || isBlank(sa.clientId()) || isBlank(sa.roleName())) {
                    r.skipped(SLICE_SA_ROLES);
                    continue;
                }
                if (!targets.containsKey(sa.clientId())) {
                    LOG.warn("Helix realm import [{}]: skipped service-account role '{}' — client '{}' not in target",
                            realmId, sa.roleName(), sa.clientId());
                    r.skipped(SLICE_SA_ROLES);
                    continue;
                }
                final Map<String, ServiceAccountRoleDto> existing = byKey(
                        clientRolePublisher.serviceAccountRoles(
                                io.helixiam.authorization.support.RealmScopedKey.pack(realmId, sa.clientId())),
                        ServiceAccountRoleDto::roleName);
                final boolean exists = existing.containsKey(sa.roleName());
                if (blocked(exists, SLICE_SA_ROLES, sa.clientId() + ":" + sa.roleName(), opts, r)) {
                    continue;
                }
                try {
                    if (exists) {
                        r.updated(SLICE_SA_ROLES); // assign is idempotent on (roleName, roleType)
                    } else {
                        clientRolePublisher.assignServiceAccountRole(new ServiceAccountRoleDto(null, realmId,
                                sa.clientId(), sa.roleName(), sa.roleType(), sa.roleClientId()));
                        r.created(SLICE_SA_ROLES);
                    }
                } catch (final RuntimeException ex) {
                    LOG.warn("Helix realm import [{}]: skipped service-account role '{}' on '{}': {}", realmId,
                            sa.roleName(), sa.clientId(), ex.toString());
                    r.skipped(SLICE_SA_ROLES);
                }
            }
        }
    }

    // --- resource indicators (RFC 8707): a per-client allow-list REPLACE; keyed by clientId. ---
    private void importResourceIndicators(final String realmId, final RealmExportDocument doc, final ImportOptions opts,
                                          final RealmImportResult.Builder r) {
        if (doc.resourceIndicators() == null) {
            return;
        }
        final Map<String, ClientDto> targets = byKey(clientPublisher.list(realmId), ClientDto::clientId);
        for (final AllowedResourcesWrite aw : doc.resourceIndicators()) {
            if (aw == null || isBlank(aw.clientId())) {
                r.skipped(SLICE_RESOURCE_INDICATORS);
                continue;
            }
            if (!targets.containsKey(aw.clientId())) {
                LOG.warn("Helix realm import [{}]: skipped resource allow-list — client '{}' not in target realm",
                        realmId, aw.clientId());
                r.skipped(SLICE_RESOURCE_INDICATORS);
                continue;
            }
            // An existing non-empty allow-list is the "already configured" condition for the conflict gate.
            final boolean exists = !nonNull(resourcePublisher.allowedResourcesForClient(
                    io.helixiam.authorization.support.RealmScopedKey.pack(realmId, aw.clientId()))).isEmpty();
            if (blocked(exists, SLICE_RESOURCE_INDICATORS, aw.clientId(), opts, r)) {
                continue;
            }
            try {
                resourcePublisher.setAllowedResourcesForClient(new AllowedResourcesWrite(realmId, aw.clientId(), aw.resources()));
                if (exists) {
                    r.updated(SLICE_RESOURCE_INDICATORS);
                } else {
                    r.created(SLICE_RESOURCE_INDICATORS);
                }
            } catch (final RuntimeException ex) {
                LOG.warn("Helix realm import [{}]: skipped resource allow-list for '{}': {}", realmId, aw.clientId(),
                        ex.toString());
                r.skipped(SLICE_RESOURCE_INDICATORS);
            }
        }
    }

    // --- UMA authorization services: keyed by clientId; server + scopes/resources/policies/permissions upserted. ---
    private void importAuthorizationServices(final String realmId, final RealmExportDocument doc,
                                             final ImportOptions opts, final RealmImportResult.Builder r) {
        if (doc.authorizationServices() == null) {
            return;
        }
        final Map<String, ClientDto> targets = byKey(clientPublisher.list(realmId), ClientDto::clientId);
        for (final ClientAuthorizationDto a : doc.authorizationServices()) {
            if (a == null || isBlank(a.clientId())) {
                r.skipped(SLICE_AUTHZ);
                continue;
            }
            if (!targets.containsKey(a.clientId())) {
                LOG.warn("Helix realm import [{}]: skipped authorization services — client '{}' not in target realm",
                        realmId, a.clientId());
                r.skipped(SLICE_AUTHZ);
                continue;
            }
            // An already-enabled resource server is the "already configured" condition for the conflict gate.
            final AuthzServerDto currentServer = authorizationPublisher.getServer(new AuthzRef(realmId, a.clientId(), null));
            final boolean exists = currentServer != null && Boolean.TRUE.equals(currentServer.enabled());
            if (blocked(exists, SLICE_AUTHZ, a.clientId(), opts, r)) {
                continue;
            }
            try {
                final AuthzServerDto server = a.server();
                authorizationPublisher.setServer(new AuthzServerDto(realmId, a.clientId(),
                        server == null ? Boolean.TRUE : server.enabled(),
                        server == null ? null : server.decisionStrategy()));
                for (final AuthzScopeDto s : nonNull(a.scopes())) {
                    if (s != null && !isBlank(s.name())) {
                        authorizationPublisher.createScope(new AuthzScopeDto(null, realmId, a.clientId(), s.name()));
                    }
                }
                for (final AuthzResourceDto res : nonNull(a.resources())) {
                    if (res != null && !isBlank(res.name())) {
                        authorizationPublisher.createResource(new AuthzResourceDto(null, realmId, a.clientId(),
                                res.name(), res.uris(), res.scopes()));
                    }
                }
                for (final AuthzPolicyDto p : nonNull(a.policies())) {
                    if (p != null && !isBlank(p.name())) {
                        authorizationPublisher.createPolicy(new AuthzPolicyDto(null, realmId, a.clientId(), p.name(),
                                p.type(), p.logic(), p.roles()));
                    }
                }
                for (final AuthzPermissionDto perm : nonNull(a.permissions())) {
                    if (perm != null && !isBlank(perm.name())) {
                        authorizationPublisher.createPermission(new AuthzPermissionDto(null, realmId, a.clientId(),
                                perm.name(), perm.type(), perm.resourceName(), perm.scopeName(), perm.policies(),
                                perm.decisionStrategy()));
                    }
                }
                if (exists) {
                    r.updated(SLICE_AUTHZ);
                } else {
                    r.created(SLICE_AUTHZ);
                }
            } catch (final RuntimeException ex) {
                LOG.warn("Helix realm import [{}]: skipped authorization services for '{}': {}", realmId, a.clientId(),
                        ex.toString());
                r.skipped(SLICE_AUTHZ);
            }
        }
    }

    private static <T> Map<String, T> byKey(final List<T> items, final java.util.function.Function<T, String> key) {
        final Map<String, T> out = new LinkedHashMap<>();
        if (items != null) {
            for (final T item : items) {
                final String k = item == null ? null : key.apply(item);
                if (k != null) {
                    out.putIfAbsent(k, item);
                }
            }
        }
        return out;
    }

    private static <T> List<T> nonNull(final List<T> in) {
        return in == null ? List.of() : in;
    }

    private static boolean isBlank(final String s) {
        return s == null || s.isBlank();
    }
}
