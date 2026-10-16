/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.federation;

import io.helixiam.authorization.domain.federation.FederatedLinkEntity;
import io.helixiam.authorization.domain.federation.LinkProvenance;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.service.adminrbac.AdminGrantGuard;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * Round 6: a realm admin decides whether a user's federated link may sign in an administrator. <b>Confirm</b> marks
 * the user's links of a provider {@code ADMIN_CONFIRMED} (for an administrator who cannot use the account console's
 * link flow); <b>revoke trust</b> marks them {@code AUTO}, so they keep working for an ordinary user but never sign in
 * an administrator (for a suspect {@code LEGACY} link). Both need realm-admin and are audited.
 */
@Service
public class FederatedLinkTrustService {

    private static final Logger LOG = LogManager.getLogger(FederatedLinkTrustService.class);

    /** A user's link, for the admin console. */
    public record LinkView(String idpAlias, String externalSubject, String createdVia, Long linkedAt,
                           boolean trustedForAdmins) {
    }

    private final FederatedLinkService links;
    private final TenantUserRepository memberships;
    private final AdminGrantGuard grants;
    private final AuditLog audit;

    public FederatedLinkTrustService(final FederatedLinkService links, final TenantUserRepository memberships,
                                     final AdminGrantGuard grants, final AuditLog audit) {
        this.links = links;
        this.memberships = memberships;
        this.grants = grants;
        this.audit = audit;
    }

    /** The links of {@code userId}, or null when the user is not in {@code realmId}. */
    public List<LinkView> list(final String realmId, final String userId) {
        if (!member(realmId, userId)) {
            return null;
        }
        return links.linksOf(userId).stream().map(FederatedLinkTrustService::view).toList();
    }

    /** Marks the user's links of {@code alias} confirmed by a realm admin; false when there are none. */
    public boolean confirm(final String realmId, final String userId, final String alias) {
        return set(realmId, userId, alias, LinkProvenance.ADMIN_CONFIRMED, "Confirming a federated link",
                "FEDERATED_LINK_CONFIRMED");
    }

    /** Marks the user's links of {@code alias} untrusted for administrators; false when there are none. */
    public boolean revokeTrust(final String realmId, final String userId, final String alias) {
        return set(realmId, userId, alias, LinkProvenance.AUTO, "Revoking trust in a federated link",
                "FEDERATED_LINK_TRUST_REVOKED");
    }

    private boolean set(final String realmId, final String userId, final String alias, final String via,
                        final String what, final String type) {
        grants.requireRealmAdmin(realmId, what);
        if (!member(realmId, userId)) {
            return false;
        }
        final int changed = links.setProvenance(userId, alias, via);
        LOG.info("{} {} of user {} in realm {}: {} link(s)", what, LogSafe.sanitize(alias), LogSafe.sanitize(userId),
                LogSafe.sanitize(realmId), changed);
        audit.emit(AuditEvent.admin(AuditContext.nowIso(), type, realmId, AuditContext.adminActor(), null, "user",
                userId, changed > 0 ? "SUCCESS" : "FAILURE",
                Map.of("idpAlias", alias, "createdVia", via, "links", String.valueOf(changed))));
        return changed > 0;
    }

    private boolean member(final String realmId, final String userId) {
        return memberships.findByTenantIdAndUserId(realmId, userId).isPresent();
    }

    private static LinkView view(final FederatedLinkEntity l) {
        final String via = LinkProvenance.normalize(l.getCreatedVia());
        return new LinkView(l.getIdpAlias(), l.getExternalSubject(), via,
                l.getCreationDate() == null ? null : l.getCreationDate().getTime(),
                LinkProvenance.mayAuthenticateAdmin(via));
    }
}
