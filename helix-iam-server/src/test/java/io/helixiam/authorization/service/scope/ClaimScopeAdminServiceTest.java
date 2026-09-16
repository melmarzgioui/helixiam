package io.helixiam.authorization.service.scope;

import io.helixiam.authorization.domain.scope.ClaimDef;
import io.helixiam.authorization.domain.scope.ClientScope;
import io.helixiam.authorization.domain.scope.ScopeClaim;
import io.helixiam.authorization.domain.scope.admin.ClaimDto;
import io.helixiam.authorization.domain.scope.admin.ClaimWriteDto;
import io.helixiam.authorization.domain.scope.admin.ScopeDetailDto;
import io.helixiam.authorization.domain.scope.admin.ScopeRef;
import io.helixiam.authorization.domain.scope.admin.ScopeWriteDto;
import io.helixiam.authorization.domain.scope.admin.SubjectClaimDto;
import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.domain.tenant.Tenant;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import io.helixiam.authorization.repository.realm.RealmConfigRepository;
import io.helixiam.authorization.repository.scope.ClaimDefRepository;
import io.helixiam.authorization.repository.scope.ClientScopeRepository;
import io.helixiam.authorization.repository.scope.ScopeClaimRepository;
import io.helixiam.authorization.repository.tenant.TenantRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E8.5: claim catalogue + client scope administration (with first-use seeding).
 */
class ClaimScopeAdminServiceTest {

    private ClaimDefRepository claims;
    private ClientScopeRepository scopes;
    private ScopeClaimRepository scopeClaims;
    private TenantRepository tenants;
    private RealmConfigRepository realmConfigs;
    private ServiceProviderRepository serviceProviders;
    private ClaimScopeAdminService service;

    @BeforeEach
    void setUp() {
        claims = mock(ClaimDefRepository.class);
        scopes = mock(ClientScopeRepository.class);
        scopeClaims = mock(ScopeClaimRepository.class);
        tenants = mock(TenantRepository.class);
        realmConfigs = mock(RealmConfigRepository.class);
        serviceProviders = mock(ServiceProviderRepository.class);
        when(tenants.findById(anyString())).thenReturn(Optional.of(mock(Tenant.class)));
        // repositories echo the saved entity (so seeding can chain scope -> claim -> mapping).
        when(scopes.save(any(ClientScope.class))).thenAnswer(inv -> inv.getArgument(0));
        when(claims.save(any(ClaimDef.class))).thenAnswer(inv -> inv.getArgument(0));
        when(scopeClaims.save(any(ScopeClaim.class))).thenAnswer(inv -> inv.getArgument(0));
        when(realmConfigs.save(any(RealmConfig.class))).thenAnswer(inv -> inv.getArgument(0));
        service = new ClaimScopeAdminService(claims, scopes, scopeClaims, tenants, realmConfigs, serviceProviders, org.mockito.Mockito.mock(io.helixiam.authorization.repository.application.ApplicationRepository.class));
    }

    @Test
    void listScopes_seedsDefaultCatalogueAndScopes_whenRealmIsEmpty() {
        when(scopes.countByTenantId("gov")).thenReturn(0L);
        when(scopes.findAllByTenantId("gov")).thenReturn(List.of());
        when(claims.findAllByTenantId("gov")).thenReturn(List.of());

        service.listScopes("gov");

        // Seeded the default scopes (Profile/Contact/Organisation/eID) and a catalogue of claims + mappings.
        verify(scopes, atLeastOnce()).save(any(ClientScope.class));
        verify(claims, atLeastOnce()).save(any(ClaimDef.class));
        verify(scopeClaims, atLeastOnce()).save(any(ScopeClaim.class));
    }

    @Test
    void listScopes_doesNotReseed_whenRealmAlreadyHasScopes() {
        when(scopes.countByTenantId("gov")).thenReturn(4L);
        when(scopes.findAllByTenantId("gov")).thenReturn(List.of());

        service.listScopes("gov");

        verify(scopes, never()).save(any(ClientScope.class));
        verify(claims, never()).save(any(ClaimDef.class));
    }

    @Test
    void createClaim_persistsANewCatalogueClaim_withMandatoryFlag() {
        when(scopes.countByTenantId("gov")).thenReturn(4L); // already seeded
        when(claims.existsByTenantIdAndClaimKey("gov", "nationality")).thenReturn(false);

        final ClaimDto dto = service.createClaim(new ClaimWriteDto("gov", null, "nationality", "Nationality", "NL", true));

        assertEquals("nationality", dto.key());
        assertEquals("Nationality", dto.label());
        assertTrue(dto.mandatory());
        verify(claims).save(any(ClaimDef.class));
    }

    @Test
    void createClaim_rejectsBlankKey() {
        final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.createClaim(new ClaimWriteDto("gov", null, "  ", "Label", "ex", false)));
        assertEquals("Claim key is required.", ex.getMessage());
        verify(claims, never()).save(any(ClaimDef.class));
    }

    @Test
    void createScope_rejectsBlankName() {
        final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.createScope(new ScopeWriteDto("gov", "  ", "desc")));
        assertEquals("Scope name is required.", ex.getMessage());
        verify(scopes, never()).save(any(ClientScope.class));
    }

    @Test
    void updateClaim_editsLabelExampleAndMandatory_butNotKey() {
        final ClaimDef claim = new ClaimDef("gov", "given_name", "Given name", "Alice", false);
        when(claims.findById(claim.getClaimId())).thenReturn(Optional.of(claim));

        final ClaimDto dto = service.updateClaim(new ClaimWriteDto("gov", claim.getClaimId(), "ignored", "First name", "Alicia", true));

        assertEquals("given_name", dto.key());   // key is immutable
        assertEquals("First name", dto.label());
        assertEquals("Alicia", dto.placeholder());
        assertTrue(dto.mandatory());
    }

    @Test
    void addClaim_mapsClaimIntoScope_whenNotAlreadyMapped() {
        when(scopeClaims.findByScopeIdAndClaimId("s-1", "c-1")).thenReturn(Optional.empty());

        assertTrue(service.addClaim(new ScopeRef("gov", "s-1", "c-1")));
        verify(scopeClaims).save(any(ScopeClaim.class));
    }

    @Test
    void addClaim_isIdempotent_whenAlreadyMapped() {
        when(scopeClaims.findByScopeIdAndClaimId("s-1", "c-1")).thenReturn(Optional.of(new ScopeClaim("s-1", "c-1")));

        assertTrue(service.addClaim(new ScopeRef("gov", "s-1", "c-1")));
        verify(scopeClaims, never()).save(any(ScopeClaim.class));
    }

    @Test
    void removeClaim_returnsFalse_whenNotMapped() {
        when(scopeClaims.findByScopeIdAndClaimId("s-1", "c-1")).thenReturn(Optional.empty());
        assertFalse(service.removeClaim(new ScopeRef("gov", "s-1", "c-1")));
    }

    @Test
    void getScope_returnsTheScopeWithItsMappedClaims() {
        when(scopes.countByTenantId("gov")).thenReturn(4L);
        final ClientScope scope = new ClientScope("gov", "Profile", "Basic profile");
        when(scopes.findById(scope.getScopeId())).thenReturn(Optional.of(scope));
        final ClaimDef claim = new ClaimDef("gov", "given_name", "Given name", "Alice", false);
        when(scopeClaims.findAllByScopeId(scope.getScopeId())).thenReturn(List.of(new ScopeClaim(scope.getScopeId(), claim.getClaimId())));
        when(claims.findById(claim.getClaimId())).thenReturn(Optional.of(claim));

        final ScopeDetailDto dto = service.getScope("gov", scope.getScopeId());

        assertEquals("Profile", dto.name());
        assertEquals(1, dto.claims().size());
        assertEquals("given_name", dto.claims().get(0).key());
    }

    @Test
    void getSubjectClaim_defaultsToSub_whenRealmHasNoOverride() {
        when(realmConfigs.findById("gov")).thenReturn(Optional.empty());
        assertEquals("sub", service.getSubjectClaim("gov"));
    }

    @Test
    void getSubjectClaim_returnsConfiguredClaim_whenSet() {
        final RealmConfig config = RealmConfig.defaults("gov");
        config.setSubjectClaim("email");
        when(realmConfigs.findById("gov")).thenReturn(Optional.of(config));
        assertEquals("email", service.getSubjectClaim("gov"));
    }

    @Test
    void resolveSubjectClaim_prefersClientOverride_overRealmAndDefault() {
        final RealmConfig config = RealmConfig.defaults("gov");
        config.setSubjectClaim("email");
        when(realmConfigs.findById("gov")).thenReturn(Optional.of(config));

        // client override wins
        assertEquals("phone_number", service.resolveSubjectClaim("gov", "phone_number"));
        // no client override -> realm default
        assertEquals("email", service.resolveSubjectClaim("gov", null));
        assertEquals("email", service.resolveSubjectClaim("gov", "  "));
    }

    @Test
    void resolveSubjectClaim_fallsBackToSub_whenNeitherClientNorRealmSet() {
        when(realmConfigs.findById("gov")).thenReturn(Optional.empty());
        assertEquals("sub", service.resolveSubjectClaim("gov", null));
    }

    @Test
    void resolveSubjectClaimForClient_usesClientOverride_thenRealm_thenSub() {
        final ServiceProviderOAuthClient client = new ServiceProviderOAuthClient();
        client.setTenantId("gov");
        client.setSubjectClaim("preferred_username");
        when(serviceProviders.findByClientIdAndRealmIdAndDeleted("portal", "gov", false)).thenReturn(Optional.of(client));
        assertEquals("preferred_username", service.resolveSubjectClaimForClient("gov", "portal"));

        client.setSubjectClaim(null); // inherit -> realm default
        final RealmConfig config = RealmConfig.defaults("gov");
        config.setSubjectClaim("email");
        when(realmConfigs.findById("gov")).thenReturn(Optional.of(config));
        assertEquals("email", service.resolveSubjectClaimForClient("gov", "portal"));
    }

    @Test
    void resolveSubjectClaimForClient_fallsBackToSub_whenClientUnknown() {
        when(serviceProviders.findByClientIdAndRealmIdAndDeleted("ghost", "gov", false)).thenReturn(Optional.empty());
        assertEquals("sub", service.resolveSubjectClaimForClient("gov", "ghost"));
    }

    @Test
    void resolveSubjectClaimForClient_isRealmScoped_whenClientIdReusedAcrossRealms() {
        // Same client id "shared" exists in two realms with different subject claims — the resolver
        // must return the claim of the client IN THE REQUESTED REALM, never the other realm's.
        final ServiceProviderOAuthClient gov = new ServiceProviderOAuthClient();
        gov.setTenantId("gov");
        gov.setSubjectClaim("preferred_username");
        when(serviceProviders.findByClientIdAndRealmIdAndDeleted("shared", "gov", false)).thenReturn(Optional.of(gov));

        final ServiceProviderOAuthClient acme = new ServiceProviderOAuthClient();
        acme.setTenantId("acme");
        acme.setSubjectClaim("email");
        when(serviceProviders.findByClientIdAndRealmIdAndDeleted("shared", "acme", false)).thenReturn(Optional.of(acme));

        assertEquals("preferred_username", service.resolveSubjectClaimForClient("gov", "shared"));
        assertEquals("email", service.resolveSubjectClaimForClient("acme", "shared"));
    }

    @Test
    void setSubjectClaim_persistsTheChosenClaim() {
        final RealmConfig config = RealmConfig.defaults("gov");
        when(realmConfigs.findById("gov")).thenReturn(Optional.of(config));

        final SubjectClaimDto dto = service.setSubjectClaim(new SubjectClaimDto("gov", "preferred_username"));

        assertEquals("preferred_username", dto.claimKey());
        assertEquals("preferred_username", config.getSubjectClaim());
        verify(realmConfigs).save(config);
    }
}
