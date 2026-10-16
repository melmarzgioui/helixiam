/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.adminrbac;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.domain.client.role.ClientServiceAccountRoleEntity;
import io.helixiam.authorization.repository.ClientServiceAccountRoleRepository;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import io.helixiam.authorization.repository.UserInRoleRepository;
import io.helixiam.authorization.repository.group.UserGroupMemberRepository;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Security review H5 (present in rc.11): <b>you cannot act on an admin more privileged than you.</b> An admin action
 * that targets a principal — a user, or a client through its service account — whose effective admin permissions are
 * not a subset of the caller's own is refused (403): resetting their password or credentials, impersonating them,
 * changing their profile, required actions or status, deleting them; revealing, setting or rotating a client's secret,
 * changing its authentication, keys, redirect URIs or grant types, deleting it. Revoking sessions stays allowed.
 *
 * <p>Effective permissions: the user's roles (direct and through groups), or the service account's realm roles, as
 * {@link AdminGrantGuard} defines what a role confers. The caller rules (system, dev-open, realm-admin) are
 * {@link AdminGrantGuard}'s.
 */
@Component
public class PrivilegedPrincipalGuard {

    private final AdminGrantGuard grants;
    private final UserInRoleRepository userRoles;
    private final UserGroupMemberRepository groupMembers;
    private final ClientServiceAccountRoleRepository saRoles;
    private final ServiceProviderRepository clients;

    public PrivilegedPrincipalGuard(final AdminGrantGuard grants, final UserInRoleRepository userRoles,
                                    final UserGroupMemberRepository groupMembers,
                                    final ClientServiceAccountRoleRepository saRoles,
                                    final ServiceProviderRepository clients) {
        this.grants = grants;
        this.userRoles = userRoles;
        this.groupMembers = groupMembers;
        this.saRoles = saRoles;
        this.clients = clients;
    }

    /** The admin permissions a user of {@code realmId} holds (direct roles and group roles). */
    public Set<String> userPermissions(final String realmId, final String userId) {
        final Set<String> out = new LinkedHashSet<>();
        if (userId == null) {
            return out;
        }
        userRoles.findAllByUserId(userId).forEach(r -> out.addAll(grants.grantsOf(realmId, r.getRoleId())));
        groupMembers.findAllByUserId(userId).forEach(m -> out.addAll(grants.grantsOfGroup(realmId, m.getGroupId())));
        return out;
    }

    /** Whether a user holds any admin permission in {@code realmId} (never auto-linked by attribute). */
    public boolean isAdmin(final String realmId, final String userId) {
        return !userPermissions(realmId, userId).isEmpty();
    }

    /**
     * The admin permissions a client's service account holds; {@code clientRef} is the client's id or its OAuth
     * client id.
     */
    public Set<String> clientPermissions(final String realmId, final String clientRef) {
        final Set<String> out = new LinkedHashSet<>();
        final String clientId = resolveClientId(realmId, clientRef);
        if (clientId == null) {
            return out;
        }
        for (final ClientServiceAccountRoleEntity r : saRoles.findAllByRealmIdAndClientIdOrderByRoleName(realmId, clientId)) {
            if (r.getRoleType() == null || "REALM".equalsIgnoreCase(r.getRoleType())) {
                out.addAll(grants.grantsOfName(realmId, r.getRoleName()));
            }
        }
        return out;
    }

    /**
     * The rule applies to admin actions: admin API requests and SCIM provisioning. A user's own self-service (account
     * console, required actions, password reset by e-mail) and start-up code are not admin actions on someone else.
     */
    static boolean adminAction() {
        final org.springframework.web.context.request.RequestAttributes attrs =
                org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();
        if (!(attrs instanceof org.springframework.web.context.request.ServletRequestAttributes sra)) {
            return false;
        }
        final String uri = sra.getRequest().getRequestURI();
        final String ctx = sra.getRequest().getContextPath();
        final String path = ctx != null && !ctx.isEmpty() && uri.startsWith(ctx) ? uri.substring(ctx.length()) : uri;
        return path.startsWith("/admin/") || path.contains("/scim/v2/");
    }

    /** 403 unless the caller holds every admin permission of the user. */
    public void requireMayActOnUser(final String realmId, final String userId, final String what) {
        if (!adminAction()) {
            return;
        }
        try {
            grants.requireMayGrant(realmId, userPermissions(realmId, userId), what);
        } catch (final AdminGrantGuard.AdminGrantDeniedException e) {
            throw new AdminGrantGuard.AdminGrantDeniedException(what + ": this user holds admin permissions you do "
                    + "not hold. Ask a realm admin.");
        }
    }

    /** 403 unless the caller holds every admin permission of the client's service account. */
    public void requireMayActOnClient(final String realmId, final String clientRef, final String what) {
        if (!adminAction()) {
            return;
        }
        try {
            grants.requireMayGrant(realmId, clientPermissions(realmId, clientRef), what);
        } catch (final AdminGrantGuard.AdminGrantDeniedException e) {
            throw new AdminGrantGuard.AdminGrantDeniedException(what + ": this client's service account holds admin "
                    + "permissions you do not hold. Ask a realm admin.");
        }
    }

    private String resolveClientId(final String realmId, final String clientRef) {
        if (clientRef == null || clientRef.isBlank()) {
            return null;
        }
        final Optional<ServiceProviderOAuthClient> byId = clients.findByIdAndRealmIdAndDeleted(clientRef, realmId, false);
        if (byId.isPresent()) {
            return byId.get().getClientId();
        }
        return clients.findByClientIdAndRealmIdAndDeleted(clientRef, realmId, false)
                .map(ServiceProviderOAuthClient::getClientId).orElse(clientRef);
    }
}
