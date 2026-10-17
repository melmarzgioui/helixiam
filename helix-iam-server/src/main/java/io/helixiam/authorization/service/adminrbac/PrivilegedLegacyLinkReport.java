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
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Round 6: federated links that existed before the upgrade to rc.12 are grandfathered ({@code LEGACY}): they keep
 * signing their users in, as in rc.11. Each administrator with such a link is reported at start-up with a WARN and a
 * {@code PRIVILEGED_LEGACY_LINK} audit event (realm, username, provider), so an operator can review it and, if it is
 * suspect, revoke trust in it ({@code POST .../users/{id}/federated-identities/{alias}/revoke-trust}). Never blocks
 * anything; a failure only logs. Runs when the application is ready, after the unresolved links are reconciled.
 */
@Component
public class PrivilegedLegacyLinkReport {

    private static final Logger LOG = LogManager.getLogger(PrivilegedLegacyLinkReport.class);

    /** Why a link is reported. */
    public enum Kind {
        /** Made before rc.12; still signs its administrator in. */
        LEGACY,
        /** Placed in a realm by the upgrade's fallback; signs no administrator in until a realm admin confirms it. */
        AMBIGUOUS
    }

    /**
     * One reported link.
     *
     * @param realm       the realm the link belongs to (signs in there)
     * @param adminRealms the realms where the user holds admin permissions
     */
    public record Finding(Kind kind, String realm, String username, String userId, String idpAlias,
                          java.util.Set<String> adminRealms) {
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

    /** Runs the report without ever failing start-up (called by {@code UnresolvedLinkReconciler} when ready). */
    public void runSafely() {
        try {
            check();
        } catch (final RuntimeException e) {
            LOG.warn("Could not check grandfathered federated links of administrators: {}", e.getClass().getSimpleName());
        }
    }

    private void report(final List<FederatedLinkEntity> rows, final Kind kind, final List<Finding> found) {
        for (final FederatedLinkEntity link : rows) {
            final String realm = link.getRealmId();
            if (realm == null) {
                continue;
            }
            // An administrator of any realm (or of master) counts, not only of the link's realm.
            final java.util.Set<String> adminRealms = guard.effectivePrivilegesEverywhere(link.getUserId()).keySet();
            if (adminRealms.isEmpty()) {
                continue;
            }
            final String username = users.findById(link.getUserId()).map(u -> u.getUsername()).orElse("?");
            found.add(new Finding(kind, realm, username, link.getUserId(), link.getIdpAlias(), Set.copyOf(adminRealms)));
            LOG.warn(kind == Kind.LEGACY
                            ? "Realm {}: administrator '{}' (admin in {}) signs in through identity provider '{}' with a "
                            + "link made before rc.12 (grandfathered). Review it; revoke trust if it is not theirs."
                            : "Realm {}: administrator '{}' (admin in {}) has a link of identity provider '{}' whose realm "
                            + "the upgrade could not tell; it signs them in only after a realm admin confirms it.",
                    LogSafe.sanitize(realm), LogSafe.sanitize(username), String.join(",", adminRealms),
                    LogSafe.sanitize(link.getIdpAlias()));
            audit.emit(AuditEvent.admin(AuditContext.nowIso(), kind == Kind.LEGACY ? "PRIVILEGED_LEGACY_LINK"
                            : "PRIVILEGED_AMBIGUOUS_LINK", realm, "system", null, "user", username, "SUCCESS",
                    Map.of("username", username, "idpAlias", link.getIdpAlias(), "kind", kind.name(),
                            "adminRealms", String.join(",", adminRealms))));
        }
    }

    /** Reports (and returns) the administrators with a grandfathered or ambiguous link. */
    public List<Finding> check() {
        final List<Finding> found = new ArrayList<>();
        report(links.legacyLinks(), Kind.LEGACY, found);
        report(links.ambiguousLinks(), Kind.AMBIGUOUS, found);
        for (final FederatedLinkEntity link : links.linksWithoutRealm()) {
            LOG.warn("A federated link of provider '{}' could not be placed in a realm by the upgrade and signs no one "
                    + "in. Link the provider again from the account console.", LogSafe.sanitize(link.getIdpAlias()));
        }
        return found;
    }
}
