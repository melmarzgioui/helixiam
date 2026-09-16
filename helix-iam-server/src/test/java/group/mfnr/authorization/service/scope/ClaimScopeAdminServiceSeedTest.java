package group.mfnr.authorization.service.scope;

import group.mfnr.authorization.domain.scope.ClaimDef;
import group.mfnr.authorization.domain.scope.ClientScope;
import group.mfnr.authorization.domain.scope.ScopeClaim;
import group.mfnr.authorization.domain.scope.admin.ClaimDto;
import group.mfnr.authorization.domain.realm.RealmConfig;
import group.mfnr.authorization.domain.tenant.Tenant;
import group.mfnr.authorization.repository.ServiceProviderRepository;
import group.mfnr.authorization.repository.application.ApplicationRepository;
import group.mfnr.authorization.repository.realm.RealmConfigRepository;
import group.mfnr.authorization.repository.scope.ClaimDefRepository;
import group.mfnr.authorization.repository.scope.ClientScopeRepository;
import group.mfnr.authorization.repository.scope.ScopeClaimRepository;
import group.mfnr.authorization.repository.tenant.TenantRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM per-realm self-registration: the default seeded claim catalogue must mark
 * {@code given_name}/{@code family_name} mandatory so the register form requires them out of the box.
 */
class ClaimScopeAdminServiceSeedTest {

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

        // Realm has no scopes yet -> ensureSeeded runs.
        when(scopes.countByTenantId(anyString())).thenReturn(0L);
        when(scopes.save(any(ClientScope.class))).thenAnswer(inv -> inv.getArgument(0));
        when(scopeClaims.save(any(ScopeClaim.class))).thenAnswer(inv -> inv.getArgument(0));

        // Accumulate saved claims so listClaims (which reads back via findAllByTenantId) sees them.
        final List<ClaimDef> saved = new ArrayList<>();
        when(claims.existsByTenantIdAndClaimKey(anyString(), anyString())).thenReturn(false);
        when(claims.save(any(ClaimDef.class))).thenAnswer(inv -> {
            final ClaimDef claim = inv.getArgument(0);
            saved.add(claim);
            return claim;
        });
        when(claims.findAllByTenantId(anyString())).thenAnswer(inv -> saved);

        service = new ClaimScopeAdminService(claims, scopes, scopeClaims, tenants, realmConfigs, serviceProviders,
                mock(ApplicationRepository.class));
    }

    @Test
    void defaultSeed_marksGivenAndFamilyNameMandatory() {
        final List<ClaimDto> claims = service.listClaims("seedrealm");
        final Map<String, Boolean> mandatoryByKey = claims.stream()
                .collect(Collectors.toMap(ClaimDto::key, ClaimDto::mandatory, (a, b) -> a));

        assertThat(mandatoryByKey).containsEntry("given_name", true);
        assertThat(mandatoryByKey).containsEntry("family_name", true);
        // Parity guard: email + sub stay mandatory; a purely optional claim stays optional.
        assertThat(mandatoryByKey).containsEntry("email", true);
        assertThat(mandatoryByKey).containsEntry("nickname", false);
    }
}
