/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.agent;

import io.helixiam.authorization.domain.agent.AgentIdentity;
import io.helixiam.authorization.domain.agent.AgentIdentityDto;
import io.helixiam.authorization.repository.agent.AgentIdentityRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Helix IAM Agent (NHI): registry CRUD over {@link AgentIdentity} plus the status lifecycle the console
 * drives — {@link #suspend}, {@link #activate} and {@link #revoke} transition an agent's {@code status},
 * and {@link #touchLastUsed} records a token issuance. Create applies the defaults (status ACTIVE, auth
 * SECRET, enabled true) and enforces the realm-unique name. All ops are realm-scoped so an id from another
 * realm is invisible. This is the registry layer only — no token issuance or claim enrichment lives here.
 */
@Service
public class AgentIdentityAdminService {

    private static final Set<String> STATUSES = Set.of("ACTIVE", "SUSPENDED", "EXPIRED", "REVOKED");
    private static final Set<String> AUTH_METHODS = Set.of("FEDERATED", "SECRET", "JWT");

    private final AgentIdentityRepository repository;

    public AgentIdentityAdminService(final AgentIdentityRepository repository) {
        this.repository = repository;
    }

    @Transactional(readOnly = true)
    public List<AgentIdentityDto> list(final String realmId) {
        return repository.findAllByRealmIdOrderByCreatedAtAsc(realmId).stream()
                .map(AgentIdentityDto::from).toList();
    }

    @Transactional(readOnly = true)
    public AgentIdentityDto get(final String realmId, final String id) {
        return repository.findById(id)
                .filter(a -> realmId.equals(a.getRealmId()))
                .map(AgentIdentityDto::from)
                .orElse(null);
    }

    /** Resolve the agent bound to an OIDC client in a realm, or {@code null} — backs token enrichment. */
    @Transactional(readOnly = true)
    public AgentIdentityDto findByClientId(final String realmId, final String clientId) {
        if (realmId == null || clientId == null) {
            return null;
        }
        return repository.findFirstByRealmIdAndClientId(realmId, clientId)
                .map(AgentIdentityDto::from)
                .orElse(null);
    }

    /**
     * Create or update an agent. On create a UUID is assigned and the defaults are applied; the realm-unique
     * name is enforced (a different agent already owning the name in the realm ⇒ {@link IllegalArgumentException}).
     */
    /** Security review H5: binding external trust to an admin service account is acting on that client. */
    private io.helixiam.authorization.service.adminrbac.PrivilegedPrincipalGuard principalGuard;
    private io.helixiam.authorization.service.adminrbac.AdminGrantGuard adminGrantGuard;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setPrincipalGuard(final io.helixiam.authorization.service.adminrbac.PrivilegedPrincipalGuard principalGuard) {
        this.principalGuard = principalGuard;
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setAdminGrantGuard(final io.helixiam.authorization.service.adminrbac.AdminGrantGuard adminGrantGuard) {
        this.adminGrantGuard = adminGrantGuard;
    }

    @Transactional
    public AgentIdentityDto save(final AgentIdentityDto dto) {
        // Review rc.3 #1: an id that belongs to another realm is never updated (nor moved into this one).
        if (dto.id() != null && !dto.id().isBlank()
                && repository.findById(dto.id()).filter(e -> !dto.realmId().equals(e.getRealmId())).isPresent()) {
            return null;
        }
        final AgentIdentity entity = (dto.id() == null || dto.id().isBlank())
                ? new AgentIdentity()
                : repository.findById(dto.id()).orElseGet(AgentIdentity::new);
        if (principalGuard != null) {
            if (dto.clientId() != null && !dto.clientId().isBlank()) {
                principalGuard.requireMayActOnClient(dto.realmId(), dto.clientId(), "Binding an agent to this client");
            }
            if (entity.getClientId() != null && !entity.getClientId().equals(dto.clientId())) {
                principalGuard.requireMayActOnClient(dto.realmId(), entity.getClientId(), "Changing this client's agent");
            }
        }
        if (adminGrantGuard != null) {
            // An agent's realm roles ride in its tokens: they must not confer admin permissions the caller lacks.
            final java.util.Set<String> conferred = new java.util.LinkedHashSet<>();
            for (final String role : io.helixiam.authorization.security.agent.AgentTokenEnricher.rawRolesFrom(dto.roles())) {
                if (role.indexOf('/') < 0 || role.startsWith("realm/")) {
                    conferred.addAll(adminGrantGuard.grantsOfName(dto.realmId(), role.substring(role.indexOf('/') + 1)));
                }
            }
            adminGrantGuard.requireMayGrant(dto.realmId(), conferred, "This agent's roles");
        }
        if (entity.getId() == null) {
            entity.setId(UUID.randomUUID().toString());
        }
        repository.findByRealmIdAndName(dto.realmId(), dto.name())
                .filter(existing -> !existing.getId().equals(entity.getId()))
                .ifPresent(existing -> {
                    throw new IllegalArgumentException(
                            "An agent named '" + dto.name() + "' already exists in this realm.");
                });
        entity.setRealmId(dto.realmId());
        entity.setName(dto.name());
        entity.setDisplayName(blankToNull(dto.displayName()));
        entity.setDescription(blankToNull(dto.description()));
        entity.setOwner(dto.owner());
        entity.setStatus(defaulted(dto.status(), "ACTIVE", STATUSES));
        entity.setAuthMethod(defaulted(dto.authMethod(), "SECRET", AUTH_METHODS));
        entity.setClientId(blankToNull(dto.clientId()));
        entity.setScopes(blankToNull(dto.scopes()));
        // FACTOR_ is Spring Security 7's sign-in factor namespace: never a role, realm or client (clientId/role).
        for (final String role : io.helixiam.authorization.security.agent.AgentTokenEnricher.rawRolesFrom(dto.roles())) {
            if (io.helixiam.authorization.security.SignInAuthorities.isFactorName(role.substring(role.indexOf('/') + 1))) {
                throw new IllegalArgumentException("Role names starting with 'FACTOR_' are reserved: " + role);
            }
        }
        entity.setRoles(blankToNull(dto.roles()));
        entity.setEnabled(dto.enabled());
        entity.setExpiresAt(dto.expiresAt() == null ? null : new Date(dto.expiresAt()));
        return AgentIdentityDto.from(repository.save(entity));
    }

    @Transactional
    public boolean delete(final String realmId, final String id) {
        final Optional<AgentIdentity> found = repository.findById(id)
                .filter(a -> realmId.equals(a.getRealmId()));
        if (principalGuard != null && found.isPresent() && found.get().getClientId() != null) {
            principalGuard.requireMayActOnClient(realmId, found.get().getClientId(), "Removing this client's agent");
        }
        found.ifPresent(repository::delete);
        return found.isPresent();
    }

    /** Transition to SUSPENDED. Returns the updated DTO, or null when the id is absent / in another realm. */
    @Transactional
    public AgentIdentityDto suspend(final String realmId, final String id) {
        return transition(realmId, id, "SUSPENDED");
    }

    /** Transition to ACTIVE. Returns the updated DTO, or null when the id is absent / in another realm. */
    @Transactional
    public AgentIdentityDto activate(final String realmId, final String id) {
        return transition(realmId, id, "ACTIVE");
    }

    /** Transition to REVOKED. Returns the updated DTO, or null when the id is absent / in another realm. */
    @Transactional
    public AgentIdentityDto revoke(final String realmId, final String id) {
        return transition(realmId, id, "REVOKED");
    }

    /** Record a token issuance (best-effort). Returns the updated DTO, or null when not found in the realm. */
    @Transactional
    public AgentIdentityDto touchLastUsed(final String realmId, final String id) {
        return repository.findById(id)
                .filter(a -> realmId.equals(a.getRealmId()))
                .map(a -> {
                    a.setLastUsedAt(new Date());
                    return AgentIdentityDto.from(repository.save(a));
                })
                .orElse(null);
    }

    private AgentIdentityDto transition(final String realmId, final String id, final String status) {
        return repository.findById(id)
                .filter(a -> realmId.equals(a.getRealmId()))
                .map(a -> {
                    a.setStatus(status);
                    return AgentIdentityDto.from(repository.save(a));
                })
                .orElse(null);
    }

    private static String defaulted(final String value, final String fallback, final Set<String> allowed) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        final String upper = value.trim().toUpperCase();
        if (!allowed.contains(upper)) {
            throw new IllegalArgumentException("Unknown value '" + value + "'; allowed: " + allowed);
        }
        return upper;
    }

    private static String blankToNull(final String s) {
        return (s == null || s.isBlank()) ? null : s;
    }
}
