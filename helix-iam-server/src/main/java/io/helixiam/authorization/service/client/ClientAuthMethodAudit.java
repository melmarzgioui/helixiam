/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.client;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Flags, at startup, private_key_jwt clients without a JWKS URL: they cannot authenticate with a key (and, since
 * V80, a DCR client registered as private_key_jwt is held to it). Logged as a warning naming realm and client id
 * (no secrets), so an operator can give them a JWKS URL or another method.
 */
@Component
public class ClientAuthMethodAudit {

    private static final Logger LOG = LogManager.getLogger(ClientAuthMethodAudit.class);
    private static final int MAX_LISTED = 50;

    private final ServiceProviderRepository clients;

    public ClientAuthMethodAudit(final ServiceProviderRepository clients) {
        this.clients = clients;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        check();
    }

    /** Logs the private_key_jwt clients without a JWKS URL; returns how many there are. */
    public int check() {
        final List<ServiceProviderOAuthClient> broken;
        try {
            broken = clients.findPrivateKeyJwtWithoutJwksUrl();
        } catch (final RuntimeException e) {
            LOG.debug("private_key_jwt client check skipped: {}", LogSafe.sanitize(e.getMessage()));
            return 0;
        }
        if (!broken.isEmpty()) {
            LOG.warn("{} private_key_jwt client(s) have no JWKS URL and cannot authenticate with a key; set a JWKS"
                    + " URL or another token endpoint auth method: {}", broken.size(),
                    LogSafe.sanitize(broken.stream().limit(MAX_LISTED)
                            .map(c -> c.getRealmId() + "/" + c.getClientId()).collect(Collectors.joining(", "))));
        }
        return broken.size();
    }
}
