/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.spi.IdentityProvider.LogoutContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

/**
 * Helix IAM SSO P9: when a brokered (federated/eID) session ends, propagate the logout to the external IdP it
 * came from. Routes the {@link LogoutContext} to the {@link IdentityProvider} named by {@code idpAlias} and
 * calls its {@code logout()}. Strictly best-effort — an unknown alias or a failing upstream is swallowed so
 * the local Helix logout always completes.
 */
@Component
public class FederatedLogoutCoordinator {

    private static final Logger LOG = LogManager.getLogger(FederatedLogoutCoordinator.class);

    private final IdentityProviderRegistry registry;

    public FederatedLogoutCoordinator(final IdentityProviderRegistry registry) {
        this.registry = registry;
    }

    /** Propagate the logout to the upstream IdP the session was brokered through ({@code idpAlias}). */
    public void propagate(final LogoutContext context) {
        if (context == null || context.idpAlias() == null || context.idpAlias().isBlank()) {
            return; // not a brokered session — nothing upstream to log out
        }
        try {
            final IdentityProvider provider = registry.get(context.idpAlias());
            if (provider == null) {
                LOG.debug("Federated logout: no provider registered for alias {}", context.idpAlias());
                return;
            }
            provider.logout(context);
            LOG.info("Federated logout propagated to upstream IdP {}", context.idpAlias());
        } catch (final RuntimeException e) {
            LOG.warn("Federated logout to {} failed (local logout already done): {}",
                    context.idpAlias(), e.getMessage());
        }
    }
}
