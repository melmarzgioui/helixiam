/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.agent;

import io.helixiam.authorization.domain.agent.AgentIdentity;
import io.helixiam.authorization.domain.agent.AgentOwnerReviewDto;
import io.helixiam.authorization.domain.audit.AuditRecord;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.agent.AgentIdentityRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import io.helixiam.authorization.service.agent.OwnerIntegrity.OwnerStatus;
import io.helixiam.authorization.service.agent.OwnerIntegrity.RealmUser;
import io.helixiam.authorization.service.audit.AuditLogService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * Owner-integrity governance for agents (NHIs):
 * <ul>
 *   <li>{@link #review(String)} — classify every agent's owner against the realm's users, so orphaned
 *       ("zombie owner") and fictional owners surface for admin review.</li>
 *   <li>{@link #cascadeOnDeprovision(String, String, String)} — when a human is disabled/deleted, suspend
 *       their still-ACTIVE agents so a departing person never leaves live, unattended NHIs behind. Each
 *       suspension is audited.</li>
 * </ul>
 */
@Service
public class AgentOwnerReviewService {

    private final AgentIdentityRepository agents;
    private final TenantUserRepository tenantUsers;
    private final UserCredentialsRepository users;
    private final AuditLogService audit;

    public AgentOwnerReviewService(final AgentIdentityRepository agents, final TenantUserRepository tenantUsers,
                                   final UserCredentialsRepository users, final AuditLogService audit) {
        this.agents = agents;
        this.tenantUsers = tenantUsers;
        this.users = users;
        this.audit = audit;
    }

    /** Every agent in the realm, each tagged with its owner-integrity verdict. */
    @Transactional(readOnly = true)
    public List<AgentOwnerReviewDto> review(final String realmId) {
        final List<RealmUser> realmUsers = realmUsers(realmId);
        return agents.findAllByRealmIdOrderByCreatedAtAsc(realmId).stream()
                .map(a -> new AgentOwnerReviewDto(a.getId(), a.getName(), a.getOwner(), a.getStatus(),
                        OwnerIntegrity.classify(a.getOwner(), realmUsers).name()))
                .toList();
    }

    /**
     * Suspend the ACTIVE agents owned by a just-deprovisioned user (matched on username or email). Agents in
     * any other state are left alone. Returns how many were suspended.
     */
    @Transactional
    public int cascadeOnDeprovision(final String realmId, final String username, final String email) {
        final String u = norm(username);
        final String e = norm(email);
        if (u.isEmpty() && e.isEmpty()) {
            return 0;
        }
        int suspended = 0;
        for (final AgentIdentity a : agents.findAllByRealmIdOrderByCreatedAtAsc(realmId)) {
            if (!"ACTIVE".equals(a.getStatus())) {
                continue;
            }
            final String owner = norm(a.getOwner());
            if ((!u.isEmpty() && owner.equals(u)) || (!e.isEmpty() && owner.equals(e))) {
                a.setStatus("SUSPENDED");
                agents.save(a);
                audit.record(new AuditRecord(Instant.now().toString(), "admin", "AGENT",
                        "agent.owner.deprovisioned.suspend", realmId, "system", null, "agent", a.getId(),
                        "success", "owner " + a.getOwner() + " was deprovisioned; agent auto-suspended"));
                suspended++;
            }
        }
        return suspended;
    }

    private List<RealmUser> realmUsers(final String realmId) {
        return tenantUsers.findAllByTenantId(realmId).stream()
                .map(link -> users.findByUserId(link.getUserId()).orElse(null))
                .filter(java.util.Objects::nonNull)
                // isEnabled() is a stub (always true); the real deprovisioned signal is isDisabled().
                .map(u -> new RealmUser(u.getUsername(), u.getEmail(), !u.isDisabled()))
                .toList();
    }

    private static String norm(final String s) {
        return s == null ? "" : s.trim().toLowerCase();
    }
}
