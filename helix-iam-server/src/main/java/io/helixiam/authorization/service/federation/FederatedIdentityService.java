/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.federation;

import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

/**
 * Helix IAM E5: the identity-domain operations the federation broker needs — resolve an existing
 * federated link, resolve a local user by email, record links, and just-in-time provision a new
 * federated user. JIT provisioning is deliberately CONSERVATIVE: the user is created usable but
 * passwordless, with NO roles and NO tenant membership — access is granted explicitly afterwards, so
 * a brokered login can never silently confer privileges.
 *
 * <p>Notes on this user model: {@code username} is the email ({@code @Email}); {@code accountLocked}
 * holds non-locked semantics ({@code isAccountNonLocked()} returns it), so {@code true} = usable.
 * Federated users are written directly (not via {@code UserService.save}, which is password +
 * signup-email oriented).
 */
@Service
public class FederatedIdentityService {

    private static final Logger LOG = LogManager.getLogger(FederatedIdentityService.class);

    private final UserCredentialsRepository users;
    private final FederatedLinkService links;

    private io.helixiam.authorization.repository.tenant.TenantUserRepository memberships;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setMemberships(final io.helixiam.authorization.repository.tenant.TenantUserRepository memberships) {
        this.memberships = memberships;
    }

    public FederatedIdentityService(final UserCredentialsRepository users, final FederatedLinkService links) {
        this.users = users;
        this.links = links;
    }

    /** The local user previously linked to this external subject for the given provider, if any. */
    public Optional<String> findLinkedUser(final String idpAlias, final String externalSubject) {
        return links.findLinkedUser(idpAlias, externalSubject).filter(this::eligibleInCurrentRealm);
    }

    /** Record (or overwrite) the federated link. */
    public void link(final String idpAlias, final String externalSubject, final String userId) {
        links.link(idpAlias, externalSubject, userId);
    }

    /** A local user with this email (the username is the email), if any. */
    public Optional<String> findUserByEmail(final String email) {
        if (email == null || email.isBlank()) {
            return Optional.empty();
        }
        final String realm = io.helixiam.authorization.security.realm.RealmContextHolder.get();
        if (realm == null) {
            return Optional.empty();
        }
        final String address = email.trim().toLowerCase();
        return users.findByRealmIdAndUsername(realm, address).or(() -> users.findByRealmIdAndEmail(realm, address))
                .map(UserCredentials::getUserId).filter(this::eligibleInCurrentRealm);
    }

    /**
     * Review rc.3 #1 (security): federation in realm X may only resolve to a user of realm X — never to a user who
     * belongs only to other realms (a realm's IdP or LDAP returning a master admin's email must not sign in as the
     * master admin). Users with no realm link at all (JIT users from before 1.0) stay eligible.
     */
    private boolean eligibleInCurrentRealm(final String userId) {
        if (memberships == null) {
            return true;
        }
        final java.util.List<io.helixiam.authorization.domain.tenant.TenantUser> links = memberships.findAllByUserId(userId);
        final String realm = io.helixiam.authorization.security.realm.RealmContextHolder.get();
        return links.isEmpty() || (realm != null && links.stream().anyMatch(l -> realm.equals(l.getTenantId())));
    }

    /**
     * Passwordless load of a user by id — backs federation session establishment after the external
     * IdP has authenticated the subject. Returns {@code null} when no such user exists.
     */
    public UserCredentials loadUser(final String userId) {
        return users.findByUserId(userId).orElse(null);
    }

    /**
     * Just-in-time provision a conservative federated user (usable, passwordless, no roles, no
     * tenant); returns its generated id.
     */
    @Transactional
    public String provisionUser(final String email, final Map<String, String> attributes) {
        // eID schemes (DigiD/eHerkenning/eIDAS) assert no email; fall back to the mapped subject-derived
        // username (BSN / PersonIdentifier / entityConcernedID) so the user always has a stable identifier.
        final String username = (email != null && !email.isBlank())
                ? email : (attributes != null ? attributes.get("username") : null);
        final UserCredentials user = new UserCredentials();
        user.setUsername(username);       // username == email, or the subject id for eID
        user.setRealmId(io.helixiam.authorization.security.realm.RealmContextHolder.get());
        user.setPassword(null);           // federated: no local password
        user.setAccountLocked(true);      // true == non-locked == usable (per isAccountNonLocked)
        if (attributes != null) {
            user.getUserAttributes().putAll(attributes);
        }
        final String userId = users.save(user).getUserId();
        // Review rc.3 #1: a JIT user belongs to the realm whose identity provider created it.
        final String realm = io.helixiam.authorization.security.realm.RealmContextHolder.get();
        if (realm != null && memberships != null) {
            final io.helixiam.authorization.domain.tenant.TenantUser link = new io.helixiam.authorization.domain.tenant.TenantUser();
            link.setTenantId(realm);
            link.setUserId(userId);
            memberships.save(link);
        }
        LOG.info("JIT-provisioned conservative federated user {} ({}) — no roles/tenant", userId, username);
        return userId;
    }
}
