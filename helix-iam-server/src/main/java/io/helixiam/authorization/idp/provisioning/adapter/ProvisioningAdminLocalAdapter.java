/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.provisioning.adapter;

import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.idp.provisioning.DcrBindRequest;
import io.helixiam.authorization.idp.provisioning.DcrRegistrationDto;
import io.helixiam.authorization.idp.provisioning.DcrTokenCheck;
import io.helixiam.authorization.idp.provisioning.ProvisioningAdminPublisher;
import io.helixiam.authorization.idp.provisioning.ProvisioningConfigDto;
import io.helixiam.authorization.idp.provisioning.ProvisioningConfigResult;
import io.helixiam.authorization.idp.provisioning.ProvisioningConfigWriteDto;
import io.helixiam.authorization.idp.provisioning.ScimTokenCheck;
import io.helixiam.authorization.service.provisioning.ProvisioningAdminService;
import org.springframework.stereotype.Component;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link ProvisioningAdminPublisher}.
 */
@Component
public class ProvisioningAdminLocalAdapter implements ProvisioningAdminPublisher {


    private final ProvisioningAdminService service;
    private final DtoBridge bridge;

    public ProvisioningAdminLocalAdapter(final ProvisioningAdminService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public ProvisioningConfigDto getConfig(final String realmId) {
        return bridge.to(service.getConfig(realmId), ProvisioningConfigDto.class);
    }

    @Override
    public ProvisioningConfigResult saveConfig(final ProvisioningConfigWriteDto write) {
        return bridge.to(service.saveConfig(bridge.to(write,
                io.helixiam.authorization.domain.provisioning.admin.ProvisioningConfigWriteDto.class)),
                ProvisioningConfigResult.class);
    }

    @Override
    public Boolean verifyScimToken(final ScimTokenCheck check) {
        return service.verifyScimToken(bridge.to(check,
                io.helixiam.authorization.domain.provisioning.admin.ScimTokenCheck.class));
    }

    @Override
    public Boolean isDcrOpen(final String realmId) {
        return service.isDcrOpen(realmId);
    }

    @Override
    public String issueInitialAccessToken(final String realmId) {
        return service.issueInitialAccessToken(realmId);
    }

    @Override
    public Boolean consumeInitialAccessToken(final ScimTokenCheck check) {
        return service.consumeInitialAccessToken(check.realmId(), check.token());
    }

    @Override
    public DcrRegistrationDto bind(final DcrBindRequest request) {
        return bridge.to(service.bind(bridge.to(request,
                io.helixiam.authorization.domain.provisioning.admin.DcrBindRequest.class)),
                DcrRegistrationDto.class);
    }

    @Override
    public Boolean verifyRegistrationToken(final DcrTokenCheck check) {
        return service.verifyRegistrationToken(bridge.to(check,
                io.helixiam.authorization.domain.provisioning.admin.DcrTokenCheck.class));
    }

    @Override
    public Boolean unbind(final DcrTokenCheck check) {
        service.unbind(check.realmId(), check.clientInternalId());
        return Boolean.TRUE;
    }
}
