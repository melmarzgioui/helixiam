/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.application;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.domain.application.ApplicationEntity;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import io.helixiam.authorization.repository.application.ApplicationRepository;
import io.helixiam.authorization.repository.realm.RealmConfigRepository;
import io.helixiam.authorization.repository.scope.ClaimDefRepository;
import io.helixiam.authorization.repository.scope.ClientScopeRepository;
import io.helixiam.authorization.repository.scope.ScopeClaimRepository;
import io.helixiam.authorization.repository.tenant.TenantRepository;
import io.helixiam.authorization.service.ServiceProviderService;
import io.helixiam.authorization.service.scope.ClaimScopeAdminService;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM (Application model): the subject-claim and login-flow resolvers walk UP to the parent
 * Application — {@code app ?? client ?? realm/browser} — falling back to the client's own value when the
 * app sets nothing. These are off the SAS hot path ({@code findByClientId} is untouched).
 */
class ApplicationPrecedenceTest {

    private final ServiceProviderRepository clients = mock(ServiceProviderRepository.class);
    private final ApplicationRepository apps = mock(ApplicationRepository.class);

    private static ServiceProviderOAuthClient client(final String applicationId, final String ownFlow,
                                                     final String ownSubject) {
        final ServiceProviderOAuthClient c = new ServiceProviderOAuthClient();
        c.setClientId("portal");
        c.setRealmId("master");
        c.setTenantId("master");
        c.setApplicationId(applicationId);
        c.setAuthFlowAlias(ownFlow);
        c.setSubjectClaim(ownSubject);
        return c;
    }

    private static ApplicationEntity app(final String subjectClaim, final String authFlowAlias) {
        final ApplicationEntity a = new ApplicationEntity();
        a.setId("master|gov");
        a.setRealmId("master");
        a.setName("gov");
        a.setSubjectClaim(subjectClaim);
        a.setAuthFlowAlias(authFlowAlias);
        return a;
    }

    // ---- login flow ----

    private ServiceProviderService flowService() {
        return new ServiceProviderService(clients, apps, "/nonexistent");
    }

    @Test
    void flow_prefersTheApplicationFlowOverTheClientsOwn() {
        when(clients.findByClientIdAndRealmIdAndDeleted("portal", "master", false))
                .thenReturn(Optional.of(client("master|gov", "client-flow", null)));
        when(apps.findById("master|gov")).thenReturn(Optional.of(app(null, "app-flow")));

        assertThat(flowService().getFlowAlias("portal", "master")).isEqualTo("app-flow");
    }

    @Test
    void flow_fallsBackToTheClientFlowWhenTheAppSetsNone() {
        when(clients.findByClientIdAndRealmIdAndDeleted("portal", "master", false))
                .thenReturn(Optional.of(client("master|gov", "client-flow", null)));
        when(apps.findById("master|gov")).thenReturn(Optional.of(app(null, "  ")));

        assertThat(flowService().getFlowAlias("portal", "master")).isEqualTo("client-flow");
    }

    @Test
    void flow_unlinkedClientUsesItsOwnFlow() {
        when(clients.findByClientIdAndRealmIdAndDeleted("portal", "master", false))
                .thenReturn(Optional.of(client(null, "client-flow", null)));

        assertThat(flowService().getFlowAlias("portal", "master")).isEqualTo("client-flow");
    }

    // ---- subject claim ----

    private ClaimScopeAdminService subjectService() {
        return new ClaimScopeAdminService(mock(ClaimDefRepository.class), mock(ClientScopeRepository.class),
                mock(ScopeClaimRepository.class), mock(TenantRepository.class), mock(RealmConfigRepository.class),
                clients, apps);
    }

    @Test
    void subject_prefersTheApplicationSubjectClaimOverTheClientsOwn() {
        when(clients.findByClientIdAndRealmIdAndDeleted("portal", "master", false))
                .thenReturn(Optional.of(client("master|gov", null, "client-subject")));
        when(apps.findById("master|gov")).thenReturn(Optional.of(app("app-subject", null)));

        assertThat(subjectService().resolveSubjectClaimForClient("master", "portal")).isEqualTo("app-subject");
    }

    @Test
    void subject_fallsBackToTheClientSubjectClaimWhenTheAppSetsNone() {
        when(clients.findByClientIdAndRealmIdAndDeleted("portal", "master", false))
                .thenReturn(Optional.of(client("master|gov", null, "client-subject")));
        when(apps.findById("master|gov")).thenReturn(Optional.of(app(null, null)));

        assertThat(subjectService().resolveSubjectClaimForClient("master", "portal")).isEqualTo("client-subject");
    }
}
