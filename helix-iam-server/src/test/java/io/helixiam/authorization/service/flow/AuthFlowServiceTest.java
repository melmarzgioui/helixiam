package io.helixiam.authorization.service.flow;

import io.helixiam.authorization.domain.flow.AuthFlowDefinition;
import io.helixiam.authorization.domain.realm.AuthFlowEntity;
import io.helixiam.authorization.domain.realm.AuthFlowExecutionEntity;
import io.helixiam.authorization.repository.realm.AuthFlowExecutionRepository;
import io.helixiam.authorization.repository.realm.AuthFlowRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM (named flows): per-client flow resolution at login time — a client's bound flow runs when it
 * exists, otherwise the realm falls back to its built-in {@code browser} flow.
 */
class AuthFlowServiceTest {

    private AuthFlowRepository flowRepository;
    private AuthFlowExecutionRepository executionRepository;
    private AuthFlowService service;

    @BeforeEach
    void setUp() {
        flowRepository = mock(AuthFlowRepository.class);
        executionRepository = mock(AuthFlowExecutionRepository.class);
        service = new AuthFlowService(flowRepository, executionRepository);
    }

    private void stubFlow(final String realm, final String alias, final String flowId, final String authenticatorId) {
        when(flowRepository.findFirstByRealmIdAndAlias(realm, alias))
                .thenReturn(Optional.of(new AuthFlowEntity(flowId, realm, alias, false)));
        when(executionRepository.findAllByFlowId(flowId)).thenReturn(List.of(
                new AuthFlowExecutionEntity("x", flowId, null, authenticatorId, "REQUIRED", false, 10)));
    }

    @Test
    void getDefinitionOrBrowser_returnsTheClientsBoundFlow_whenItExists() {
        stubFlow("gov", "step-up-strong", "flow-strong", "webauthn");

        final AuthFlowDefinition def = service.getDefinitionOrBrowser("gov", "step-up-strong");

        assertEquals("step-up-strong", def.getAlias());
        assertEquals("webauthn", def.getExecutions().get(0).getAuthenticatorId());
    }

    @Test
    void getDefinitionOrBrowser_fallsBackToBrowser_whenTheBoundFlowIsMissing() {
        when(flowRepository.findFirstByRealmIdAndAlias("gov", "deleted-flow")).thenReturn(Optional.empty());
        stubFlow("gov", "browser", "flow-browser", "otp");

        final AuthFlowDefinition def = service.getDefinitionOrBrowser("gov", "deleted-flow");

        assertEquals("browser", def.getAlias());
    }

    @Test
    void getDefinitionOrBrowser_usesBrowser_whenNoAliasGiven() {
        stubFlow("gov", "browser", "flow-browser", "otp");

        assertEquals("browser", service.getDefinitionOrBrowser("gov", null).getAlias());
        assertEquals("browser", service.getDefinitionOrBrowser("gov", "  ").getAlias());
    }
}
