/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.adminrbac;

import io.helixiam.authorization.domain.federation.FederatedLinkEntity;
import io.helixiam.authorization.domain.tenant.TenantUser;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.service.federation.FederatedLinkService;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Round 6: federated links that existed before the upgrade to rc.12 are grandfathered ({@code LEGACY}): they keep
 * signing their users in, as in rc.11. Each administrator with such a link is reported at start-up with a WARN and a
 * {@code PRIVILEGED_LEGACY_LINK} audit event (realm, username, provider), so an operator can review it and, if it is
 * suspect, revoke trust in it ({@code POST .../users/{id}/federated-identities/{alias}/revoke-trust}). Never blocks
 * anything; a failure only logs.
 */
@Component
public class PrivilegedLegacyLinkReport implements ApplicationRunner {

    private static final Logger LOG = LogManager.getLogger(PrivilegedLegacyLinkReport.class);

    /** One reported link. */
    public record Finding(String realm, String username, String userId, String idpAlias) {
    }

    private final FederatedLinkService links;
    @SuppressWarnings("unused") // kept for the constructor signature (Spring wiring)
    private final TenantUserRepository memberships;
    private final UserCredentialsRepository users;
    private final PrivilegedPrincipalGuard guard;
    private final AuditLog audit;

    public PrivilegedLegacyLinkReport(final FederatedLinkService links, final TenantUserRepository memberships,
                                      final UserCredentialsRepository users, final PrivilegedPrincipalGuard guard,
                                      final AuditLog audit) {
        this.links = links;
        this.memberships = memberships;
        this.users = users;
        this.guard = guard;
        this.audit = audit;
    }

    @Override
    public void run(final ApplicationArguments args) {
        try {
            check();
        } catch (final RuntimeException e) {
            LOG.warn("Could not check grandfathered federated links of administrators: {}", e.getClass().getSimpleName());
        }
    }

    /** Reports (and returns) the administrators with a grandfathered link. */
    public List<Finding> check() {
        final List<Finding> found = new ArrayList<>();
        for (final FederatedLinkEntity link : links.legacyLinks()) {
            final String realm = link.getRealmId();
            if (realm == null || !guard.isAdmin(realm, link.getUserId())) {
                continue;
            }
            final String username = users.findById(link.getUserId()).map(u -> u.getUsername()).orElse("?");
            found.add(new Finding(realm, username, link.getUserId(), link.getIdpAlias()));
            LOG.warn("Realm {}: administrator '{}' signs in through identity provider '{}' with a link made before "
                            + "rc.12 (grandfathered). Review it; revoke trust if it is not theirs.",
                    LogSafe.sanitize(realm), LogSafe.sanitize(username), LogSafe.sanitize(link.getIdpAlias()));
            audit.emit(AuditEvent.admin(AuditContext.nowIso(), "PRIVILEGED_LEGACY_LINK", realm, "system", null,
                    "user", username, "SUCCESS", Map.of("username", username, "idpAlias", link.getIdpAlias())));
        }
        for (final FederatedLinkEntity link : links.linksWithoutRealm()) {
            LOG.warn("A federated link of provider '{}' could not be placed in a realm by the upgrade and signs no one "
                    + "in. Link the provider again from the account console.", LogSafe.sanitize(link.getIdpAlias()));
        }
        return found;
    }
}
