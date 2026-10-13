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
    private final boolean dev;

    /** Production rules (no dev exception for http://localhost JWKS URLs). */
    public ClientAuthMethodAudit(final ServiceProviderRepository clients) {
        this(clients, io.helixiam.common.startup.DeploymentProfile.production());
    }

    @org.springframework.beans.factory.annotation.Autowired
    public ClientAuthMethodAudit(final ServiceProviderRepository clients,
                                 final io.helixiam.common.startup.DeploymentProfile profile) {
        this.clients = clients;
        this.dev = profile.isDev();
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        check();
    }

    /**
     * Logs the private_key_jwt clients without a JWKS URL, and those whose JWKS URL breaks the https rule (rows stored
     * before it; the token endpoint refuses to fetch them, so they cannot authenticate); returns how many in total.
     */
    public int check() {
        return withoutJwksUrl() + nonHttpsJwksUrl();
    }

    private int nonHttpsJwksUrl() {
        final List<ServiceProviderOAuthClient> legacy;
        try {
            legacy = clients.findPrivateKeyJwtWithJwksUrl().stream()
                    .filter(c -> JwksUrlPolicy.problem(c.getJwksUrl(), dev) != null).toList();
        } catch (final RuntimeException e) {
            LOG.debug("private_key_jwt JWKS URL check skipped: {}", LogSafe.sanitize(e.getMessage()));
            return 0;
        }
        if (!legacy.isEmpty()) {
            LOG.warn("{} private_key_jwt client(s) have a JWKS URL that is not https; the token endpoint refuses to"
                    + " fetch it, so they cannot authenticate until the URL is changed to https: {}", legacy.size(),
                    LogSafe.sanitize(legacy.stream().limit(MAX_LISTED)
                            .map(c -> c.getRealmId() + "/" + c.getClientId()).collect(Collectors.joining(", "))));
        }
        return legacy.size();
    }

    private int withoutJwksUrl() {
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
