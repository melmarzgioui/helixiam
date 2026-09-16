package group.mfnr.authorization.controller.admin.io;

import group.mfnr.authorization.amqp.authz.AuthorizationPublisher;
import group.mfnr.authorization.amqp.authz.AuthzPermissionDto;
import group.mfnr.authorization.amqp.authz.AuthzPolicyDto;
import group.mfnr.authorization.amqp.authz.AuthzResourceDto;
import group.mfnr.authorization.amqp.authz.AuthzScopeDto;
import group.mfnr.authorization.amqp.authz.AuthzServerDto;
import group.mfnr.authorization.amqp.client.ClientAdminPublisher;
import group.mfnr.authorization.amqp.client.ClientDto;
import group.mfnr.authorization.amqp.client.ClientWriteDto;
import group.mfnr.authorization.amqp.clientrole.ClientRoleDto;
import group.mfnr.authorization.amqp.clientrole.ClientRolePublisher;
import group.mfnr.authorization.amqp.clientrole.ServiceAccountRoleDto;
import group.mfnr.authorization.amqp.mapper.ClientMapperPublisher;
import group.mfnr.authorization.amqp.mapper.ProtocolMapperDto;
import group.mfnr.authorization.amqp.resource.AllowedResourcesWrite;
import group.mfnr.authorization.amqp.resource.ResourceIndicatorPublisher;
import group.mfnr.authorization.amqp.federation.IdentityProviderConfig;
import group.mfnr.authorization.amqp.federation.IdentityProviderConfigPublisher;
import group.mfnr.authorization.amqp.flow.FlowAdminPublisher;
import group.mfnr.authorization.amqp.flow.FlowCreateDto;
import group.mfnr.authorization.amqp.flow.FlowDefinitionDto;
import group.mfnr.authorization.amqp.flow.FlowSaveDto;
import group.mfnr.authorization.amqp.flow.FlowSummaryDto;
import group.mfnr.authorization.amqp.org.OrgDto;
import group.mfnr.authorization.amqp.org.OrgWriteDto;
import group.mfnr.authorization.amqp.org.OrganizationAdminPublisher;
import group.mfnr.authorization.amqp.realm.RealmAdminPublisher;
import group.mfnr.authorization.amqp.realm.RealmSettingsDto;
import group.mfnr.authorization.amqp.role.RoleAdminPublisher;
import group.mfnr.authorization.amqp.role.RoleDto;
import group.mfnr.authorization.amqp.role.RoleRef;
import group.mfnr.authorization.amqp.saml.SamlRelyingPartyConfig;
import group.mfnr.authorization.amqp.saml.SamlRelyingPartyConfigPublisher;
import group.mfnr.authorization.amqp.scope.ClaimDto;
import group.mfnr.authorization.amqp.scope.ClaimScopePublisher;
import group.mfnr.authorization.amqp.scope.ClaimWriteDto;
import group.mfnr.authorization.amqp.scope.ClientScopeDto;
import group.mfnr.authorization.amqp.scope.ScopeDetailDto;
import group.mfnr.authorization.amqp.scope.ScopeWriteDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM: the import service upserts each slice by natural key and is idempotent — importing the same
 * document twice updates rather than duplicates. Backed by tiny in-memory fake stores so the second
 * import sees what the first one wrote.
 */
class RealmImportServiceTest {

    private RealmAdminPublisher realm;
    private ClientAdminPublisher clients;
    private SamlRelyingPartyConfigPublisher saml;
    private RoleAdminPublisher roles;
    private ClaimScopePublisher scopes;
    private IdentityProviderConfigPublisher idps;
    private FlowAdminPublisher flows;
    private OrganizationAdminPublisher orgs;
    private group.mfnr.authorization.amqp.application.ApplicationConfigPublisher apps;
    private group.mfnr.authorization.amqp.webhook.WebhookConfigPublisher webhooks;
    private group.mfnr.authorization.amqp.scim.ScimTargetConfigPublisher scims;
    private group.mfnr.authorization.amqp.workloadidentity.WorkloadIdentityConfigPublisher workloads;
    private group.mfnr.authorization.amqp.group.GroupAdminPublisher groupPub;
    private group.mfnr.authorization.amqp.user.UserAdminPublisher userPub;
    private ClientMapperPublisher mapperPub;
    private ClientRolePublisher clientRolePub;
    private ResourceIndicatorPublisher resourcePub;
    private AuthorizationPublisher authzPub;
    private org.springframework.mock.env.MockEnvironment environment;
    private RealmImportService service;

    // In-memory stores keyed by natural key.
    private final List<ClientDto> clientStore = new ArrayList<>();
    private final List<RoleDto> roleStore = new ArrayList<>();
    private final List<ClientScopeDto> scopeStore = new ArrayList<>();
    private final List<ClaimDto> claimStore = new ArrayList<>();
    private final List<SamlRelyingPartyConfig> samlStore = new ArrayList<>();
    private final List<IdentityProviderConfig> idpStore = new ArrayList<>();
    private final List<FlowSummaryDto> flowStore = new ArrayList<>();
    private final List<OrgDto> orgStore = new ArrayList<>();
    private final AtomicInteger seq = new AtomicInteger(1);

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
        apps = mock(group.mfnr.authorization.amqp.application.ApplicationConfigPublisher.class);
        webhooks = mock(group.mfnr.authorization.amqp.webhook.WebhookConfigPublisher.class);
        scims = mock(group.mfnr.authorization.amqp.scim.ScimTargetConfigPublisher.class);
        workloads = mock(group.mfnr.authorization.amqp.workloadidentity.WorkloadIdentityConfigPublisher.class);
        groupPub = mock(group.mfnr.authorization.amqp.group.GroupAdminPublisher.class);
        userPub = mock(group.mfnr.authorization.amqp.user.UserAdminPublisher.class);
        mapperPub = mock(ClientMapperPublisher.class);
        clientRolePub = mock(ClientRolePublisher.class);
        resourcePub = mock(ResourceIndicatorPublisher.class);
        authzPub = mock(AuthorizationPublisher.class);
        environment = new org.springframework.mock.env.MockEnvironment();
        service = new RealmImportService(realm, clients, saml, roles, scopes, idps, flows, orgs,
                apps, webhooks, scims, workloads,
                mock(group.mfnr.authorization.amqp.messaging.MessagingAdminPublisher.class),
                mock(group.mfnr.authorization.amqp.adminrbac.AdminRbacPublisher.class),
                groupPub, userPub, environment,
                mapperPub, clientRolePub, resourcePub, authzPub,
                mock(group.mfnr.authorization.amqp.agent.AgentIdentityPublisher.class));

        wireClients();
        wireRoles();
        wireScopes();
        wireSaml();
        wireIdps();
        wireFlows();
        wireOrgs();
    }

    @Test
    void firstImportCreates_secondImportUpdates_neverDuplicates() {
        final RealmExportDocument doc = sampleDoc();

        final RealmImportResult first = service.importInto("gov", doc);
        assertThat(first.slices().get(RealmImportService.SLICE_CLIENTS).created()).isEqualTo(1);
        assertThat(first.slices().get(RealmImportService.SLICE_ROLES).created()).isEqualTo(1);
        assertThat(first.slices().get(RealmImportService.SLICE_SCOPES).created()).isEqualTo(1);
        assertThat(first.slices().get(RealmImportService.SLICE_SAML).created()).isEqualTo(1);
        assertThat(first.slices().get(RealmImportService.SLICE_IDPS).created()).isEqualTo(1);
        assertThat(first.slices().get(RealmImportService.SLICE_FLOWS).created()).isEqualTo(1);
        assertThat(first.slices().get(RealmImportService.SLICE_ORGS).created()).isEqualTo(1);

        final RealmImportResult second = service.importInto("gov", doc);
        assertThat(second.slices().get(RealmImportService.SLICE_CLIENTS).updated()).isEqualTo(1);
        assertThat(second.slices().get(RealmImportService.SLICE_CLIENTS).created()).isZero();
        assertThat(second.slices().get(RealmImportService.SLICE_ROLES).updated()).isEqualTo(1);
        assertThat(second.slices().get(RealmImportService.SLICE_SCOPES).updated()).isEqualTo(1);
        assertThat(second.slices().get(RealmImportService.SLICE_SAML).updated()).isEqualTo(1);
        assertThat(second.slices().get(RealmImportService.SLICE_IDPS).updated()).isEqualTo(1);
        assertThat(second.slices().get(RealmImportService.SLICE_FLOWS).updated()).isEqualTo(1);
        assertThat(second.slices().get(RealmImportService.SLICE_ORGS).updated()).isEqualTo(1);

        // No duplicates landed in any store.
        assertThat(clientStore).hasSize(1);
        assertThat(roleStore).hasSize(1);
        assertThat(scopeStore).hasSize(1);
        assertThat(samlStore).hasSize(1);
        assertThat(idpStore).hasSize(1);
        assertThat(flowStore).hasSize(1);
        assertThat(orgStore).hasSize(1);
    }

    @Test
    void realmIdFromPathOverridesDocument() {
        service.importInto("target", sampleDoc());
        final RealmSettingsDto saved = realmSaved();
        assertThat(saved.realmId()).isEqualTo("target");
        assertThat(saved.captchaSecretKey()).isNull();
    }

    @Test
    void clientImportNeverWritesSecret() {
        service.importInto("gov", sampleDoc());
        // create then update (2nd import): captured writes never carry a secret (ClientWriteDto has none).
        final org.mockito.ArgumentCaptor<ClientWriteDto> captor = org.mockito.ArgumentCaptor.forClass(ClientWriteDto.class);
        verify(clients).create(captor.capture());
        assertThat(captor.getValue().clientId()).isEqualTo("web-app");
        // ClientWriteDto structurally has no secret field — compile-time guarantee; assert id null on create.
        assertThat(captor.getValue().id()).isNull();
    }

    @Test
    void blankNaturalKeysAreSkipped() {
        final RealmExportDocument doc = new RealmExportDocument(1, null,
                List.of(new ClientDto("x", null, "  ", null, null, null, null, null, null, null, null, null, null,
                        null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
                        null, null, null, null, null)),
                null, List.of(new RoleDto("x", null, "")), null, null, null, null);
        final RealmImportResult result = service.importInto("gov", doc);
        assertThat(result.slices().get(RealmImportService.SLICE_CLIENTS).skipped()).isEqualTo(1);
        assertThat(result.slices().get(RealmImportService.SLICE_ROLES).skipped()).isEqualTo(1);
        verify(clients, never()).create(any());
        verify(roles, never()).create(any());
    }

    @Test
    void nullDocumentYieldsEmptyResult() {
        assertThat(service.importInto("gov", null).slices()).isEmpty();
    }

    @Test
    void skipMode_leavesExistingEntitiesUntouched() {
        final RealmExportDocument doc = sampleDoc();
        service.importInto("gov", doc); // first import creates everything

        final RealmImportResult skipped =
                service.importInto("gov", doc, new ImportOptions(ImportOptions.OnConflict.SKIP));

        assertThat(skipped.slices().get(RealmImportService.SLICE_CLIENTS).skipped()).isEqualTo(1);
        assertThat(skipped.slices().get(RealmImportService.SLICE_CLIENTS).updated()).isZero();
        assertThat(skipped.slices().get(RealmImportService.SLICE_ROLES).skipped()).isEqualTo(1);
        assertThat(skipped.slices().get(RealmImportService.SLICE_ORGS).skipped()).isEqualTo(1);
        assertThat(skipped.conflicts()).isNull(); // SKIP blocks silently
        // existing entries were never re-written, and nothing duplicated
        verify(clients, never()).update(any());
        assertThat(clientStore).hasSize(1);
        assertThat(roleStore).hasSize(1);
    }

    @Test
    void failMode_recordsEachConflictAndDoesNotOverwrite() {
        final RealmExportDocument doc = sampleDoc();
        service.importInto("gov", doc); // first import creates everything

        final RealmImportResult failed =
                service.importInto("gov", doc, new ImportOptions(ImportOptions.OnConflict.FAIL));

        assertThat(failed.conflicts()).isNotNull();
        assertThat(failed.conflicts())
                .contains("clients:web-app", "roles:admin", "organizations:acme", "samlClients:sp1",
                        "identityProviders:google", "flows:custom", "clientScopes:profile");
        assertThat(failed.slices().get(RealmImportService.SLICE_CLIENTS).updated()).isZero();
        verify(clients, never()).update(any());
    }

    @Test
    void idpSecretPlaceholderResolvedFromEnvironmentOnImport() {
        environment.setProperty("HELIX_GOV_IDP_GOOGLE_CLIENTSECRET", "real-secret");
        final java.util.Map<String, String> cfg = new java.util.LinkedHashMap<>();
        cfg.put("clientId", "abc");
        cfg.put("clientSecret", "${HELIX_GOV_IDP_GOOGLE_CLIENTSECRET}");
        final IdentityProviderConfig idp = new IdentityProviderConfig("src", "google", "oidc", "Google", true, cfg);
        final RealmExportDocument doc = new RealmExportDocument(2, null, null, null, null, null,
                List.of(idp), null, null);

        service.importInto("gov", doc);

        final org.mockito.ArgumentCaptor<IdentityProviderConfig> cap =
                org.mockito.ArgumentCaptor.forClass(IdentityProviderConfig.class);
        verify(idps).save(cap.capture());
        assertThat(cap.getValue().config()).containsEntry("clientSecret", "real-secret"); // ${...} resolved
        assertThat(cap.getValue().config()).containsEntry("clientId", "abc");
    }

    @Test
    void missingSecretEnvLeavesUnsetUnderDefaultPolicy() {
        final java.util.Map<String, String> cfg = new java.util.LinkedHashMap<>();
        cfg.put("clientSecret", "${HELIX_GOV_IDP_GOOGLE_CLIENTSECRET}"); // never set on the environment
        final IdentityProviderConfig idp = new IdentityProviderConfig("src", "google", "oidc", "Google", true, cfg);
        final RealmExportDocument doc = new RealmExportDocument(2, null, null, null, null, null,
                List.of(idp), null, null);

        service.importInto("gov", doc, new ImportOptions(ImportOptions.OnConflict.OVERWRITE));

        final org.mockito.ArgumentCaptor<IdentityProviderConfig> cap =
                org.mockito.ArgumentCaptor.forClass(IdentityProviderConfig.class);
        verify(idps).save(cap.capture());
        assertThat(cap.getValue().config().get("clientSecret")).isNull(); // unresolved → left unset
    }

    @Test
    void newSlices_applicationCreated_andWebhookSecretResolved() {
        environment.setProperty("HELIX_GOV_WEBHOOK_AUDIT_SECRET", "hmac-key");
        final group.mfnr.authorization.amqp.application.ApplicationConfig app =
                new group.mfnr.authorization.amqp.application.ApplicationConfig("src", "billing-suite", "Billing",
                        "email", "browser", true, "Billing Suite");
        final group.mfnr.authorization.amqp.webhook.WebhookSubscriptionDto wh =
                new group.mfnr.authorization.amqp.webhook.WebhookSubscriptionDto(null, "src", "audit", "https://hook",
                        "${HELIX_GOV_WEBHOOK_AUDIT_SECRET}", true, "LOGIN", true, null);
        final RealmExportDocument doc = new RealmExportDocument(2, null, null, null, null, null, null, null, null,
                List.of(app), List.of(wh), null, null, null, null, null, null, null, null, null, null, null, null,
                null, null);

        final RealmImportResult res = service.importInto("gov", doc);

        final org.mockito.ArgumentCaptor<group.mfnr.authorization.amqp.application.ApplicationConfig> appCap =
                org.mockito.ArgumentCaptor.forClass(group.mfnr.authorization.amqp.application.ApplicationConfig.class);
        verify(apps).save(appCap.capture());
        assertThat(appCap.getValue().realmId()).isEqualTo("gov");      // realm retargeted from path
        assertThat(appCap.getValue().name()).isEqualTo("billing-suite");
        assertThat(res.slices().get(RealmImportService.SLICE_APPLICATIONS).created()).isEqualTo(1);

        final org.mockito.ArgumentCaptor<group.mfnr.authorization.amqp.webhook.WebhookSubscriptionDto> whCap =
                org.mockito.ArgumentCaptor.forClass(group.mfnr.authorization.amqp.webhook.WebhookSubscriptionDto.class);
        verify(webhooks).save(whCap.capture());
        assertThat(whCap.getValue().url()).isEqualTo("https://hook");   // field-order guard for the positional record
        assertThat(whCap.getValue().secret()).isEqualTo("hmac-key");    // ${...} resolved from env
        assertThat(whCap.getValue().name()).isEqualTo("audit");
    }

    @Test
    void groupHierarchyRemapped_andUserRolesAssigned() {
        roleStore.add(new RoleDto("gov", "role-1", "ledger-writer"));
        when(groupPub.create(any())).thenAnswer(inv -> {
            final group.mfnr.authorization.amqp.group.GroupWriteDto w = inv.getArgument(0);
            return new group.mfnr.authorization.amqp.group.GroupDto(w.realmId(), "gid-" + w.name(), w.name(),
                    w.parentId(), 0, List.of());
        });
        when(userPub.create(any())).thenAnswer(inv -> {
            final group.mfnr.authorization.amqp.user.UserWriteDto w = inv.getArgument(0);
            return new group.mfnr.authorization.amqp.user.UserAdminDto(w.realmId(), "uid-" + w.username(),
                    w.username(), w.email(), w.enabled(), w.locked(), false, List.of(), w.attributes(), 0L);
        });

        final group.mfnr.authorization.amqp.group.GroupDto parent =
                new group.mfnr.authorization.amqp.group.GroupDto("src", "src-staff", "staff", null, 0, List.of());
        final group.mfnr.authorization.amqp.group.GroupDto child =
                new group.mfnr.authorization.amqp.group.GroupDto("src", "src-fin", "finance", "src-staff", 0,
                        List.of("ledger-writer"));
        final group.mfnr.authorization.amqp.user.UserAdminDto user =
                new group.mfnr.authorization.amqp.user.UserAdminDto("src", "src-u1", "alice", "alice@x.io", true, false,
                        false, List.of("ledger-writer"), java.util.Map.of(), 0L);
        final RealmExportDocument doc = new RealmExportDocument(2, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, List.of(parent, child), List.of(user), null, null, null,
                null, null, null, null);

        final RealmImportResult res = service.importInto("gov", doc);

        // both groups created; the child's parent id is REMAPPED from the source id to the target group id
        final org.mockito.ArgumentCaptor<group.mfnr.authorization.amqp.group.GroupWriteDto> gw =
                org.mockito.ArgumentCaptor.forClass(group.mfnr.authorization.amqp.group.GroupWriteDto.class);
        verify(groupPub, org.mockito.Mockito.times(2)).create(gw.capture());
        final group.mfnr.authorization.amqp.group.GroupWriteDto childWrite = gw.getAllValues().stream()
                .filter(w -> "finance".equals(w.name())).findFirst().orElseThrow();
        assertThat(childWrite.parentId()).isEqualTo("gid-staff"); // not the source "src-staff"
        assertThat(res.slices().get(RealmImportService.SLICE_GROUPS).created()).isEqualTo(2);
        verify(groupPub).assignRole(any()); // child group's role mapping applied

        // user created and its realm role assigned via the re-mapped role id
        final org.mockito.ArgumentCaptor<group.mfnr.authorization.amqp.role.RoleAssignment> ra =
                org.mockito.ArgumentCaptor.forClass(group.mfnr.authorization.amqp.role.RoleAssignment.class);
        verify(roles).assign(ra.capture());
        assertThat(ra.getValue().userId()).isEqualTo("uid-alice");
        assertThat(ra.getValue().roleId()).isEqualTo("role-1");
        assertThat(res.slices().get(RealmImportService.SLICE_USERS).created()).isEqualTo(1);
    }

    @Test
    void perClientSlices_createdForExistingClient() {
        clientStore.add(clientDto("web-app"));
        // existing-detection lookups all empty/disabled → every entry is created.
        when(mapperPub.list(any())).thenReturn(List.of());
        when(clientRolePub.listRoles(any())).thenReturn(List.of());
        when(clientRolePub.serviceAccountRoles(any())).thenReturn(List.of());
        when(resourcePub.allowedResourcesForClient(any())).thenReturn(List.of());
        when(authzPub.getServer(any())).thenReturn(new AuthzServerDto("gov", "web-app", false, "UNANIMOUS"));

        final RealmExportDocument doc = docWithPerClientSlices(
                List.of(new ProtocolMapperDto(null, "src", "web-app", "email-claim", "USER_ATTRIBUTE", "email",
                        "email", true, true)),
                List.of(new ClientRoleDto(null, "src", "web-app", "viewer", "Viewer")),
                List.of(new ServiceAccountRoleDto(null, "src", "web-app", "admin", "REALM", null)),
                List.of(new AllowedResourcesWrite("src", "web-app", List.of("https://api"))),
                List.of(new ClientAuthorizationDto("web-app",
                        new AuthzServerDto("src", "web-app", true, "UNANIMOUS"),
                        List.of(new AuthzScopeDto(null, "src", "web-app", "read")),
                        List.of(new AuthzResourceDto(null, "src", "web-app", "doc", List.of("/d"), List.of("read"))),
                        List.of(new AuthzPolicyDto(null, "src", "web-app", "viewers", "ROLE", "POSITIVE",
                                List.of("viewer"))),
                        List.of(new AuthzPermissionDto(null, "src", "web-app", "read-doc", "scope", "doc", "read",
                                List.of("viewers"), "UNANIMOUS")))));

        final RealmImportResult res = service.importInto("gov", doc);

        verify(mapperPub).create(any());
        verify(clientRolePub).createRole(any());
        verify(clientRolePub).assignServiceAccountRole(any());
        verify(resourcePub).setAllowedResourcesForClient(any());
        verify(authzPub).setServer(any());
        verify(authzPub).createScope(any());
        verify(authzPub).createResource(any());
        verify(authzPub).createPolicy(any());
        verify(authzPub).createPermission(any());
        assertThat(res.slices().get(RealmImportService.SLICE_CLIENT_MAPPERS).created()).isEqualTo(1);
        assertThat(res.slices().get(RealmImportService.SLICE_CLIENT_ROLES).created()).isEqualTo(1);
        assertThat(res.slices().get(RealmImportService.SLICE_SA_ROLES).created()).isEqualTo(1);
        assertThat(res.slices().get(RealmImportService.SLICE_RESOURCE_INDICATORS).created()).isEqualTo(1);
        assertThat(res.slices().get(RealmImportService.SLICE_AUTHZ).created()).isEqualTo(1);
    }

    @Test
    void perClientSlices_skipMode_leavesExistingUntouched() {
        clientStore.add(clientDto("web-app"));
        // existing-detection lookups report the config already present → SKIP must block every write.
        when(mapperPub.list(any())).thenReturn(List.of(new ProtocolMapperDto("m1", "gov", "web-app", "email-claim",
                "USER_ATTRIBUTE", "email", "email", true, true)));
        when(clientRolePub.listRoles(any())).thenReturn(List.of(new ClientRoleDto("r1", "gov", "web-app", "viewer",
                "V")));
        when(clientRolePub.serviceAccountRoles(any())).thenReturn(List.of(new ServiceAccountRoleDto("s1", "gov",
                "web-app", "admin", "REALM", null)));
        when(resourcePub.allowedResourcesForClient(any())).thenReturn(List.of("https://api"));
        when(authzPub.getServer(any())).thenReturn(new AuthzServerDto("gov", "web-app", true, "UNANIMOUS"));

        final RealmExportDocument doc = docWithPerClientSlices(
                List.of(new ProtocolMapperDto(null, "src", "web-app", "email-claim", "USER_ATTRIBUTE", "email",
                        "email", true, true)),
                List.of(new ClientRoleDto(null, "src", "web-app", "viewer", "V")),
                List.of(new ServiceAccountRoleDto(null, "src", "web-app", "admin", "REALM", null)),
                List.of(new AllowedResourcesWrite("src", "web-app", List.of("https://api"))),
                List.of(new ClientAuthorizationDto("web-app", new AuthzServerDto("src", "web-app", true, "UNANIMOUS"),
                        List.of(), List.of(), List.of(), List.of())));

        final RealmImportResult res = service.importInto("gov", doc,
                new ImportOptions(ImportOptions.OnConflict.SKIP));

        assertThat(res.slices().get(RealmImportService.SLICE_CLIENT_MAPPERS).skipped()).isEqualTo(1);
        assertThat(res.slices().get(RealmImportService.SLICE_CLIENT_ROLES).skipped()).isEqualTo(1);
        assertThat(res.slices().get(RealmImportService.SLICE_SA_ROLES).skipped()).isEqualTo(1);
        assertThat(res.slices().get(RealmImportService.SLICE_RESOURCE_INDICATORS).skipped()).isEqualTo(1);
        assertThat(res.slices().get(RealmImportService.SLICE_AUTHZ).skipped()).isEqualTo(1);
        verify(mapperPub, never()).create(any());
        verify(clientRolePub, never()).createRole(any());
        verify(clientRolePub, never()).assignServiceAccountRole(any());
        verify(resourcePub, never()).setAllowedResourcesForClient(any());
        verify(authzPub, never()).setServer(any());
    }

    @Test
    void perClientSlices_unknownClientSkipped() {
        // clientStore is empty → "ghost" resolves to no client in the target realm.
        final RealmExportDocument doc = docWithPerClientSlices(
                List.of(new ProtocolMapperDto(null, "src", "ghost", "m", "USER_ATTRIBUTE", "email", "email", true,
                        true)),
                List.of(new ClientRoleDto(null, "src", "ghost", "viewer", "V")),
                List.of(new ServiceAccountRoleDto(null, "src", "ghost", "admin", "REALM", null)),
                List.of(new AllowedResourcesWrite("src", "ghost", List.of("https://api"))),
                List.of(new ClientAuthorizationDto("ghost", new AuthzServerDto("src", "ghost", true, "U"),
                        List.of(), List.of(), List.of(), List.of())));

        final RealmImportResult res = service.importInto("gov", doc);

        assertThat(res.slices().get(RealmImportService.SLICE_CLIENT_MAPPERS).skipped()).isEqualTo(1);
        assertThat(res.slices().get(RealmImportService.SLICE_CLIENT_ROLES).skipped()).isEqualTo(1);
        assertThat(res.slices().get(RealmImportService.SLICE_SA_ROLES).skipped()).isEqualTo(1);
        assertThat(res.slices().get(RealmImportService.SLICE_RESOURCE_INDICATORS).skipped()).isEqualTo(1);
        assertThat(res.slices().get(RealmImportService.SLICE_AUTHZ).skipped()).isEqualTo(1);
        verify(mapperPub, never()).create(any());
        verify(clientRolePub, never()).createRole(any());
        verify(clientRolePub, never()).assignServiceAccountRole(any());
        verify(resourcePub, never()).setAllowedResourcesForClient(any());
        verify(authzPub, never()).setServer(any());
    }

    /** A document carrying only the 5 per-client config slices (every other slice null). */
    private static RealmExportDocument docWithPerClientSlices(final List<ProtocolMapperDto> mappers,
                                                              final List<ClientRoleDto> clientRoles,
                                                              final List<ServiceAccountRoleDto> saRoles,
                                                              final List<AllowedResourcesWrite> resourceIndicators,
                                                              final List<ClientAuthorizationDto> authz) {
        return new RealmExportDocument(2, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null, null,
                mappers, clientRoles, saRoles, resourceIndicators, authz, null, null);
    }

    private static ClientDto clientDto(final String clientId) {
        return new ClientDto("gov", "cid-" + clientId, clientId, List.of(), List.of(), List.of(), null, "sub", null,
                clientId, null, List.of(), List.of(), false, false, false, null, null, null, null, false, null, null,
                null, false, null, null, null, null, null, null, null, null);
    }

    private RealmSettingsDto realmSaved() {
        final org.mockito.ArgumentCaptor<RealmSettingsDto> c = org.mockito.ArgumentCaptor.forClass(RealmSettingsDto.class);
        verify(realm).save(c.capture());
        return c.getValue();
    }

    // --- sample document ---
    private static RealmExportDocument sampleDoc() {
        final RealmSettingsDto rs = new RealmSettingsDto("source", "Gov", "https://issuer", 300, 3600, false, false,
                8, true, 1800, 36000, false, 0, false, 5, 900, 900, false, false, false, false, false, false, 0,
                false, "recaptcha", "site", null, 0, false, false, 0, 0, "none", "none", "none",
                null, null, null, null, null, true);
        final ClientDto c = new ClientDto("source", null, "web-app", List.of("authorization_code"), List.of("https://cb"),
                List.of("openid"), null, "sub", null, "Web", null, List.of(), List.of(), false, false, false, null,
                null, null, null, false, null, null, null, false, null, null, null, null, null, null, null, null);
        final RoleDto role = new RoleDto("source", null, "admin");
        final ScopeDetailDto scope = new ScopeDetailDto("source", null, "profile", "Profile",
                List.of(new ClaimDto("source", null, "given_name", "Given name", null, false)));
        final SamlRelyingPartyConfig sp = new SamlRelyingPartyConfig("source", "sp1", "https://acs", null, null,
                "CERT", true, null, null);
        final IdentityProviderConfig idp = new IdentityProviderConfig("source", "google", "oidc", "Google", true,
                java.util.Map.of("clientId", "abc"));
        final FlowDefinitionDto flow = new FlowDefinitionDto("source", "custom", false, List.of());
        final OrgDto org = new OrgDto("source", null, "acme", "Acme", List.of("acme.com"), true, 0, null);
        return new RealmExportDocument(1, rs, List.of(c), List.of(sp), List.of(role), List.of(scope), List.of(idp),
                List.of(flow), List.of(org));
    }

    // --- stateful fakes ---
    private void wireClients() {
        when(clients.list(any())).thenReturn(clientStore);
        when(clients.create(any())).thenAnswer(inv -> {
            final ClientWriteDto w = inv.getArgument(0);
            final ClientDto saved = new ClientDto(w.realmId(), "cid" + seq.getAndIncrement(), w.clientId(), w.grantTypes(),
                    w.redirectUris(), w.scopes(), null, w.subjectClaim(), w.authFlowAlias(), w.name(), w.description(),
                    w.postLogoutRedirectUris(), w.webOrigins(), w.publicClient(), w.consentRequired(),
                    w.displayOnConsentScreen(), w.loginTheme(), w.rootUrl(), w.homeUrl(), w.adminUrl(),
                    w.alwaysDisplayInConsole(), w.accessTokenLifespan(), w.refreshTokenLifespan(),
                    w.idTokenSignatureAlg(), w.reuseRefreshTokens(), w.tokenEndpointAuthMethod(), w.jwksUrl(),
                    w.backchannelLogoutUri(), w.frontchannelLogoutUri(), w.applicationId(),
                    w.x509CertificateBoundAccessTokens(), w.requireSignedRequestObject(), w.jarmResponseMode());
            clientStore.add(saved);
            return saved;
        });
        when(clients.update(any())).thenAnswer(inv -> {
            final ClientWriteDto w = inv.getArgument(0);
            return clientStore.stream().filter(x -> x.clientId().equals(w.clientId())).findFirst().orElse(null);
        });
    }

    private void wireRoles() {
        when(roles.list(any())).thenReturn(roleStore);
        when(roles.create(any())).thenAnswer(inv -> {
            final RoleRef ref = inv.getArgument(0);
            final RoleDto saved = new RoleDto(ref.realmId(), "rid" + seq.getAndIncrement(), ref.name());
            roleStore.add(saved);
            return saved;
        });
    }

    private void wireScopes() {
        when(scopes.scopes(any())).thenReturn(scopeStore);
        when(scopes.claims(any())).thenReturn(claimStore);
        when(scopes.createScope(any())).thenAnswer(inv -> {
            final ScopeWriteDto w = inv.getArgument(0);
            final ClientScopeDto saved = new ClientScopeDto(w.realmId(), "sid" + seq.getAndIncrement(), w.name(),
                    w.description(), 0, List.of());
            scopeStore.add(saved);
            return saved;
        });
        when(scopes.createClaim(any())).thenAnswer(inv -> {
            final ClaimWriteDto w = inv.getArgument(0);
            final ClaimDto saved = new ClaimDto(w.realmId(), "clm" + seq.getAndIncrement(), w.key(), w.label(),
                    w.placeholder(), w.mandatory());
            claimStore.add(saved);
            return saved;
        });
        when(scopes.addClaim(any())).thenReturn(true);
    }

    private void wireSaml() {
        when(saml.list(any())).thenReturn(samlStore);
        when(saml.save(any())).thenAnswer(inv -> {
            final SamlRelyingPartyConfig sp = inv.getArgument(0);
            samlStore.removeIf(x -> x.entityId().equals(sp.entityId()));
            samlStore.add(sp);
            return sp;
        });
    }

    private void wireIdps() {
        when(idps.list(any())).thenReturn(idpStore);
        when(idps.save(any())).thenAnswer(inv -> {
            final IdentityProviderConfig idp = inv.getArgument(0);
            idpStore.removeIf(x -> x.alias().equals(idp.alias()));
            idpStore.add(idp);
            return idp;
        });
    }

    private void wireFlows() {
        when(flows.list(any())).thenReturn(flowStore);
        when(flows.create(any())).thenAnswer(inv -> {
            final FlowCreateDto d = inv.getArgument(0);
            final FlowSummaryDto saved = new FlowSummaryDto(d.realmId(), d.alias(), false);
            flowStore.add(saved);
            return saved;
        });
        when(flows.save(any())).thenAnswer(inv -> {
            final FlowSaveDto d = inv.getArgument(0);
            return new FlowDefinitionDto(d.realmId(), d.alias(), false, d.executions());
        });
    }

    private void wireOrgs() {
        when(orgs.list(any())).thenReturn(orgStore);
        when(orgs.create(any())).thenAnswer(inv -> {
            final OrgWriteDto w = inv.getArgument(0);
            final OrgDto saved = new OrgDto(w.realmId(), "oid" + seq.getAndIncrement(), w.name(), w.displayName(),
                    w.domains(), w.enabled(), 0, null);
            orgStore.add(saved);
            return saved;
        });
        when(orgs.update(any())).thenAnswer(inv -> {
            final OrgWriteDto w = inv.getArgument(0);
            return orgStore.stream().filter(x -> x.name().equals(w.name())).findFirst().orElse(null);
        });
    }
}
