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
    public record LinkView(String idpAlias, String externalSubject, String subjectHint, String createdVia,
                           Long linkedAt, boolean trustedForAdmins) {
    }

    private final FederatedLinkService links;
    private io.helixiam.authorization.service.adminrbac.PrivilegedPrincipalGuard privileged;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setPrivilegedPrincipalGuard(
            final io.helixiam.authorization.service.adminrbac.PrivilegedPrincipalGuard privileged) {
        this.privileged = privileged;
    }
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
        return links.linksOf(realmId, userId).stream().map(FederatedLinkTrustService::view).toList();
    }

    /** Marks one link (alias + external subject) confirmed by a realm admin; false when the user has no such link. */
    public boolean confirm(final String realmId, final String userId, final String alias, final String subject) {
        return set(realmId, userId, alias, subject, LinkProvenance.ADMIN_CONFIRMED, "Confirming a federated link",
                "FEDERATED_LINK_CONFIRMED");
    }

    /** Marks one link untrusted for administrators; false when the user has no such link. */
    public boolean revokeTrust(final String realmId, final String userId, final String alias, final String subject) {
        return set(realmId, userId, alias, subject, LinkProvenance.AUTO, "Revoking trust in a federated link",
                "FEDERATED_LINK_TRUST_REVOKED");
    }

    private boolean set(final String realmId, final String userId, final String alias, final String subject,
                        final String via, final String what, final String type) {
        grants.requireRealmAdmin(realmId, what);
        if (!member(realmId, userId)) {
            return false;
        }
        // The link signs the user in to this realm only, but as whoever the user is: an administrator of another
        // realm (or of master) is one here too. Trusting or distrusting it needs the user's permissions everywhere.
        if (privileged != null) {
            privileged.requireMayActOnUserEverywhere(userId, what);
        }
        // Round 6 (review): exactly one link, never every link of the user to this provider.
        final boolean changed = links.setProvenance(realmId, userId, alias, subject, via);
        LOG.info("{} {} of user {} in realm {}: {}", what, LogSafe.sanitize(alias), LogSafe.sanitize(userId),
                LogSafe.sanitize(realmId), changed ? "changed" : "no such link");
        audit.emit(AuditEvent.admin(AuditContext.nowIso(), type, realmId, AuditContext.adminActor(), null, "user",
                userId, changed ? "SUCCESS" : "FAILURE",
                Map.of("idpAlias", alias, "externalSubject", mask(subject), "createdVia", via)));
        return changed;
    }

    /** The external subject as shown in the console and the audit log: its ends only. */
    public static String mask(final String subject) {
        if (subject == null) {
            return "";
        }
        return subject.length() <= 8 ? "…" + subject.substring(Math.max(0, subject.length() - 3))
                : subject.substring(0, 4) + "…" + subject.substring(subject.length() - 4);
    }

    private boolean member(final String realmId, final String userId) {
        return memberships.existsByTenantIdAndUserId(realmId, userId);
    }

    private static LinkView view(final FederatedLinkEntity l) {
        // UNRESOLVED is shown as such (it is never trusted, like AUTO, but the reason differs).
        final String via = LinkProvenance.UNRESOLVED.equals(l.getCreatedVia()) ? LinkProvenance.UNRESOLVED
                : LinkProvenance.normalize(l.getCreatedVia());
        return new LinkView(l.getIdpAlias(), l.getExternalSubject(), mask(l.getExternalSubject()), via,
                l.getCreationDate() == null ? null : l.getCreationDate().getTime(),
                LinkProvenance.mayAuthenticateAdmin(via));
    }
}
