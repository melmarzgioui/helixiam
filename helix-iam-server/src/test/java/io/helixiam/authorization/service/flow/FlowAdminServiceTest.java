/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.flow;

import io.helixiam.authorization.domain.flow.admin.FlowDefinitionDto;
import io.helixiam.authorization.domain.flow.admin.FlowExecutionDto;
import io.helixiam.authorization.domain.flow.admin.FlowSaveDto;
import io.helixiam.authorization.domain.realm.AuthFlowEntity;
import io.helixiam.authorization.domain.realm.AuthFlowExecutionEntity;
import io.helixiam.authorization.repository.realm.AuthFlowExecutionRepository;
import io.helixiam.authorization.repository.realm.AuthFlowRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E8.5-S4: Auth-flow editor — read a realm's flow as a tree and replace its executions.
 */
class FlowAdminServiceTest {

    private AuthFlowRepository flowRepository;
    private AuthFlowExecutionRepository executionRepository;
    private AuthFlowService authFlowService;
    private FlowAdminService service;

    @BeforeEach
    void setUp() {
        flowRepository = mock(AuthFlowRepository.class);
        executionRepository = mock(AuthFlowExecutionRepository.class);
        authFlowService = mock(AuthFlowService.class);
        service = new FlowAdminService(authFlowService, flowRepository, executionRepository);
    }

    @Test
    void get_seedsBrowserFlow_thenReturnsItsExecutions() {
        final AuthFlowEntity flow = new AuthFlowEntity("flow-1", "gov", "browser", true);
        when(flowRepository.findFirstByRealmIdAndAlias("gov", "browser")).thenReturn(Optional.of(flow));
        when(executionRepository.findAllByFlowId("flow-1")).thenReturn(List.of(
                new AuthFlowExecutionEntity("e1", "flow-1", null, "password", "REQUIRED", false, 10),
                new AuthFlowExecutionEntity("e2", "flow-1", null, "otp", "CONDITIONAL", false, 20)));

        final FlowDefinitionDto dto = service.get("gov", "browser");

        verify(authFlowService).ensureBrowserFlow("gov");
        assertEquals("browser", dto.alias());
        assertTrue(dto.builtIn());
        assertEquals(2, dto.executions().size());
        assertEquals("password", dto.executions().get(0).authenticatorId());
        assertEquals("CONDITIONAL", dto.executions().get(1).requirement());
    }

    @Test
    void save_replacesAllExecutions_withTheSubmittedSet() {
        final AuthFlowEntity flow = new AuthFlowEntity("flow-1", "gov", "browser", true);
        when(flowRepository.findFirstByRealmIdAndAlias("gov", "browser")).thenReturn(Optional.of(flow));
        when(executionRepository.findAllByFlowId("flow-1")).thenReturn(List.of());

        service.save(new FlowSaveDto("gov", "browser", List.of(
                new FlowExecutionDto("e1", null, "password", "REQUIRED", false, 10),
                new FlowExecutionDto("e2", null, "webauthn", "ALTERNATIVE", false, 20))));

        verify(executionRepository).deleteByFlowId("flow-1");
        final ArgumentCaptor<List<AuthFlowExecutionEntity>> captor = ArgumentCaptor.forClass(List.class);
        verify(executionRepository).saveAll(captor.capture());
        final List<AuthFlowExecutionEntity> saved = captor.getValue();
        assertEquals(2, saved.size());
        assertEquals("flow-1", saved.get(0).getFlowId());
        assertEquals("password", saved.get(0).getAuthenticatorId());
        assertEquals("ALTERNATIVE", saved.get(1).getRequirement());
        assertEquals(20, saved.get(1).getPriority());
    }

    @Test
    void save_thenGet_roundTripsPerExecutionConfigAsJson() {
        final AuthFlowEntity flow = new AuthFlowEntity("flow-1", "gov", "browser", true);
        when(flowRepository.findFirstByRealmIdAndAlias("gov", "browser")).thenReturn(Optional.of(flow));
        when(executionRepository.findAllByFlowId("flow-1")).thenReturn(List.of());

        // Save an idp-redirect step carrying config; capture what is persisted, and assert the returned
        // DTO carries the same config back (the save() return path re-reads the entity config JSON).
        final FlowDefinitionDto saved = service.save(new FlowSaveDto("gov", "browser", List.of(
                new FlowExecutionDto("e1", null, "idp-redirect", "REQUIRED", false, 10,
                        java.util.Map.of("providerAlias", "digid", "mode", "REDIRECT")))));

        final ArgumentCaptor<List<AuthFlowExecutionEntity>> captor = ArgumentCaptor.forClass(List.class);
        verify(executionRepository).saveAll(captor.capture());
        final AuthFlowExecutionEntity entity = captor.getValue().get(0);
        assertTrue(entity.getConfig().contains("\"providerAlias\":\"digid\""), entity.getConfig());
        assertTrue(entity.getConfig().contains("\"mode\":\"REDIRECT\""), entity.getConfig());

        assertEquals("digid", saved.executions().get(0).config().get("providerAlias"));
        assertEquals("REDIRECT", saved.executions().get(0).config().get("mode"));
    }

    @Test
    void save_leavesConfigNullForStepsWithoutConfig() {
        final AuthFlowEntity flow = new AuthFlowEntity("flow-1", "gov", "browser", true);
        when(flowRepository.findFirstByRealmIdAndAlias("gov", "browser")).thenReturn(Optional.of(flow));
        when(executionRepository.findAllByFlowId("flow-1")).thenReturn(List.of());

        service.save(new FlowSaveDto("gov", "browser", List.of(
                new FlowExecutionDto("e1", null, "password", "REQUIRED", false, 10))));

        final ArgumentCaptor<List<AuthFlowExecutionEntity>> captor = ArgumentCaptor.forClass(List.class);
        verify(executionRepository).saveAll(captor.capture());
        org.junit.jupiter.api.Assertions.assertNull(captor.getValue().get(0).getConfig());
    }

    @Test
    void save_seedsTheBrowserFlow_thenReplacesItsExecutions() {
        // ensureBrowserFlow (mocked here) is what materialises the row; the repo then finds it.
        when(flowRepository.findFirstByRealmIdAndAlias("gov", "browser"))
                .thenReturn(Optional.of(new AuthFlowEntity("flow-1", "gov", "browser", true)));

        service.save(new FlowSaveDto("gov", "browser", List.of()));

        verify(authFlowService).ensureBrowserFlow("gov");
        verify(executionRepository).deleteByFlowId("flow-1");
        verify(executionRepository).saveAll(any());
    }
}
