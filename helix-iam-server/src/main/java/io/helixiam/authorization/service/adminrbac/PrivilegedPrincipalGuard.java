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
    private final io.helixiam.authorization.repository.UserRolesRepository roles;
    private final io.helixiam.authorization.repository.group.UserGroupRoleRepository groupRoles;

    public PrivilegedPrincipalGuard(final AdminGrantGuard grants, final UserInRoleRepository userRoles,
                                    final UserGroupMemberRepository groupMembers,
                                    final ClientServiceAccountRoleRepository saRoles,
                                    final ServiceProviderRepository clients,
                                    final io.helixiam.authorization.repository.UserRolesRepository roles,
                                    final io.helixiam.authorization.repository.group.UserGroupRoleRepository groupRoles) {
        this.roles = roles;
        this.groupRoles = groupRoles;
        this.grants = grants;
        this.userRoles = userRoles;
        this.groupMembers = groupMembers;
        this.saRoles = saRoles;
        this.clients = clients;
    }

    /**
     * The admin permissions a user holds in {@code realmId}: the union of every authority that reaches the realm —
     * its roles in the realm, and roles of other realms that administer it (a master-realm admin administers every
     * realm) — evaluated exactly as {@code AdminAuthorizationManager} evaluates a session; group roles count too.
     */
    public Set<String> userPermissions(final String realmId, final String userId) {
        final Set<String> out = new LinkedHashSet<>();
        if (userId == null) {
            return out;
        }
        final java.util.List<String> authorities = new java.util.ArrayList<>();
        userRoles.findAllByUserId(userId).forEach(r -> roles.findById(r.getRoleId())
                .ifPresent(role -> authorities.add(role.getTenantRoleName())));
        groupMembers.findAllByUserId(userId).forEach(m -> groupRoles.findAllByGroupId(m.getGroupId())
                .forEach(gr -> roles.findById(gr.getRoleId()).ifPresent(role -> authorities.add(role.getTenantRoleName()))));
        out.addAll(grants.permissionsOfAuthorities(authorities, realmId));
        // Role-by-role too (the role named admin is realm admin of its realm by name).
        userRoles.findAllByUserId(userId).forEach(r -> out.addAll(grants.grantsOf(realmId, r.getRoleId())));
        groupMembers.findAllByUserId(userId).forEach(m -> out.addAll(grants.grantsOfGroup(realmId, m.getGroupId())));
        return out;
    }

    /**
     * Round 6: <b>the single source</b> of a target user's privilege. Realm → the admin permissions the user holds there,
     * for every realm that can reach them: their realm memberships, the realms of their roles and of their groups'
     * roles, and master. Only realms where they hold something are listed. Every check on a target user (acting on
     * them, trusting their links, changing a provider they sign in through, the start-up report, the broker) goes
     * through this, never through one realm's view.
     */
    public java.util.Map<String, Set<String>> effectivePrivilegesEverywhere(final String userId) {
        final java.util.Map<String, Set<String>> out = new java.util.LinkedHashMap<>();
        if (userId == null) {
            return out;
        }
        final Set<String> realms = new LinkedHashSet<>();
        realms.add("master");
        if (memberships != null) {
            realms.addAll(memberships.findTenantIdsByUserId(userId));
        }
        userRoles.findAllByUserId(userId).forEach(r -> roles.findById(r.getRoleId())
                .ifPresent(role -> realms.add(role.getTenantId())));
        groupMembers.findAllByUserId(userId).forEach(m -> groupRoles.findAllByGroupId(m.getGroupId())
                .forEach(gr -> roles.findById(gr.getRoleId()).ifPresent(role -> realms.add(role.getTenantId()))));
        for (final String realm : realms) {
            if (realm == null) {
                continue;
            }
            final Set<String> held = userPermissions(realm, userId);
            if (!held.isEmpty()) {
                out.put(realm, held);
            }
        }
        return out;
    }

    /** Whether a user holds any admin permission in any realm. */
    public boolean isAdminAnywhere(final String userId) {
        return !effectivePrivilegesEverywhere(userId).isEmpty();
    }

    /**
     * Whether a user is an administrator anywhere ({@link #effectivePrivilegesEverywhere}). The realm is kept for the
     * callers' signature only: an administrator of another realm or of master counts in every realm.
     */
    public boolean isAdmin(final String realmId, final String userId) {
        return isAdminAnywhere(userId);
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
        // The client's tokens also carry the realm roles of an agent bound to it (AgentTokenEnricher).
        if (agents != null) {
            agents.findFirstByRealmIdAndClientId(realmId, clientId).ifPresent(agent -> {
                for (final String role : io.helixiam.authorization.security.agent.AgentTokenEnricher.rawRolesFrom(agent.getRoles())) {
                    if (role.indexOf('/') < 0 || role.startsWith("realm/")) {
                        out.addAll(grants.grantsOfName(realmId, role.substring(role.indexOf('/') + 1)));
                    }
                }
            });
        }
        return out;
    }

    /**
     * 403 unless the caller holds, in every realm where the user holds admin permissions
     * ({@link #effectivePrivilegesEverywhere}), those permissions. {@code realmId} is the realm the action is in; an
     * administrator of another realm or of master is protected there too.
     */
    public void requireMayActOnUser(final String realmId, final String userId, final String what) {
        final java.util.Optional<AdminActor> actor = AdminActor.current();
        if (actor.isPresent() && actor.get().kind() == AdminActor.Kind.SELF) {
            if (userId != null && userId.equals(actor.get().selfUserId())) {
                return; // a user acting on their own account
            }
        }
        for (final java.util.Map.Entry<String, Set<String>> e : effectivePrivilegesEverywhere(userId).entrySet()) {
            try {
                grants.requireMayGrant(e.getKey(), e.getValue(), what);
            } catch (final AdminGrantGuard.AdminGrantDeniedException denied) {
                throw new AdminGrantGuard.AdminGrantDeniedException(what + ": this user holds admin permissions you do "
                        + "not hold" + (e.getKey().equals(realmId) ? "" : " (in realm " + e.getKey() + ")")
                        + " (or no acting administrator was declared). Ask a realm admin.");
            }
        }
    }

    /** {@link #requireMayActOnUser} for decisions that are not tied to one realm. */
    public void requireMayActOnUserEverywhere(final String userId, final String what) {
        requireMayActOnUser(null, userId, what);
    }

    /** 403 unless the caller holds every admin permission of the client's service account. */
    public void requireMayActOnClient(final String realmId, final String clientRef, final String what) {
        try {
            grants.requireMayGrant(realmId, clientPermissions(realmId, clientRef), what);
        } catch (final AdminGrantGuard.AdminGrantDeniedException e) {
            throw new AdminGrantGuard.AdminGrantDeniedException(what + ": this client's service account holds admin "
                    + "permissions you do not hold. Ask a realm admin.");
        }
    }

    private io.helixiam.authorization.repository.agent.AgentIdentityRepository agents;
    private io.helixiam.authorization.repository.federation.FederatedLinkRepository links;
    private io.helixiam.authorization.repository.tenant.TenantUserRepository memberships;
    private io.helixiam.authorization.repository.application.ApplicationRepository applications;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setSignInSurfaces(final io.helixiam.authorization.repository.federation.FederatedLinkRepository links,
                                  final io.helixiam.authorization.repository.tenant.TenantUserRepository memberships,
                                  final io.helixiam.authorization.repository.application.ApplicationRepository applications) {
        this.links = links;
        this.memberships = memberships;
        this.applications = applications;
    }

    // ------------------------------------------------------------------------------------------------ sign-in surfaces

    /**
     * Changing or deleting an identity provider needs, for every user of the realm linked to it, that user's admin
     * permissions everywhere ({@link #requireMayActOnUser}): whoever controls the provider can sign in as them.
     */
    public void requireMayChangeIdentityProvider(final String realmId, final String alias, final String what) {
        if (links == null || alias == null) {
            return;
        }
        for (final io.helixiam.authorization.domain.federation.FederatedLinkEntity l
                : links.findAllByRealmIdAndIdpAlias(realmId, alias)) {
            try {
                requireMayActOnUser(realmId, l.getUserId(), what);
            } catch (final AdminGrantGuard.AdminGrantDeniedException e) {
                throw new AdminGrantGuard.AdminGrantDeniedException(what + ": administrators sign in through this "
                        + "identity provider and hold admin permissions you do not hold. Ask a realm admin.");
            }
        }
    }

    /**
     * The flows administrators sign in through: the realm's browser flow, and the flows bound to the built-in sign-in
     * clients or their Applications.
     */
    public Set<String> protectedFlows(final String realmId) {
        final Set<String> out = new LinkedHashSet<>();
        out.add(io.helixiam.authorization.service.flow.AuthFlowService.BROWSER_FLOW);
        for (final String clientId : io.helixiam.authorization.service.client.ClientAdminService.SIGN_IN_CLIENTS) {
            clients.findByClientIdAndRealmIdAndDeleted(clientId, realmId, false).ifPresent(c -> {
                if (c.getAuthFlowAlias() != null) {
                    out.add(c.getAuthFlowAlias());
                }
                if (c.getApplicationId() != null && applications != null) {
                    applications.findById(c.getApplicationId()).ifPresent(a -> {
                        if (a.getAuthFlowAlias() != null) {
                            out.add(a.getAuthFlowAlias());
                        }
                    });
                }
            });
        }
        return out;
    }

    /** Editing, creating, renaming or deleting a flow administrators sign in through needs realm-admin. */
    public void requireMayChangeFlow(final String realmId, final String alias, final String what) {
        if (alias != null && protectedFlows(realmId).contains(alias)) {
            grants.requireRealmAdmin(realmId, what + " (administrators sign in through this flow)");
        }
    }

    /** Whether the Application {@code name} is the parent of a built-in sign-in client. */
    public boolean isSignInApplication(final String realmId, final String name) {
        final String key = io.helixiam.authorization.domain.application.ApplicationEntity.key(realmId, name);
        return clients.findAllByApplicationIdAndDeleted(key, false).stream()
                .anyMatch(c -> io.helixiam.authorization.service.client.ClientAdminService.SIGN_IN_CLIENTS
                        .contains(c.getClientId()));
    }

    /** Changing or deleting the parent Application of a built-in sign-in client needs realm-admin. */
    public void requireMayChangeApplication(final String realmId, final String name, final String what) {
        if (isSignInApplication(realmId, name)) {
            grants.requireRealmAdmin(realmId, what + " (it holds a built-in sign-in client)");
        }
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setAgents(final io.helixiam.authorization.repository.agent.AgentIdentityRepository agents) {
        this.agents = agents;
    }

    /** Whether {@code clientRef} (id or OAuth client id) is a built-in sign-in client (console, CLI). */
    public boolean isSignInClient(final String realmId, final String clientRef) {
        return io.helixiam.authorization.service.client.ClientAdminService.SIGN_IN_CLIENTS
                .contains(resolveClientId(realmId, clientRef));
    }

    /** Changing anything of a built-in sign-in client besides its cosmetic fields needs realm-admin. */
    public void requireMayChangeSignInClient(final String realmId, final String clientRef, final String what) {
        if (isSignInClient(realmId, clientRef)) {
            grants.requireRealmAdmin(realmId, what + " of a built-in sign-in client");
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
