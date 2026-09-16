/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.adapter;

import io.helixiam.authorization.amqp.AuthFlowPublisher;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.flow.persistence.AuthFlowDefinition;
import io.helixiam.authorization.service.ServiceProviderService;
import io.helixiam.authorization.service.flow.AuthFlowService;
import io.helixiam.authorization.support.RealmScopedKey;
import org.springframework.stereotype.Component;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link AuthFlowPublisher}. The domain-side {@code io.helixiam.authorization.domain.flow.AuthFlowDefinition}
 * is bridged to the flow-engine's {@link AuthFlowDefinition} (the two-copy DTO the login exchange used).
 */
@Component
public class AuthFlowLocalAdapter implements AuthFlowPublisher {

    private final AuthFlowService authFlowService;
    private final ServiceProviderService serviceProviderService;
    private final DtoBridge bridge;

    public AuthFlowLocalAdapter(final AuthFlowService authFlowService,
                                final ServiceProviderService serviceProviderService,
                                final DtoBridge bridge) {
        this.authFlowService = authFlowService;
        this.serviceProviderService = serviceProviderService;
        this.bridge = bridge;
    }

    @Override
    public AuthFlowDefinition retrieveBrowserFlow(final String realmId) {
        return bridge.to(authFlowService.getDefinition(realmId, AuthFlowService.BROWSER_FLOW),
                AuthFlowDefinition.class);
    }

    @Override
    public AuthFlowDefinition retrieveFlowForClient(final String realmScopedClientId) {
        final String[] parts = RealmScopedKey.split(realmScopedClientId);
        final String realm = parts[0];
        final String clientId = parts[1];
        final String alias = serviceProviderService.getFlowAlias(clientId, realm);
        return bridge.to(authFlowService.getDefinitionOrBrowser(realm, alias), AuthFlowDefinition.class);
    }
}
