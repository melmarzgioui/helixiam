/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.federation.spi.AttributeMapper;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Helix IAM E5.1: maps a normalized {@link BrokeredIdentity} (from any {@code IdentityProvider}) to a
 * local user, applying account linking + just-in-time provisioning + attribute mapping per the
 * realm's {@link AccountLinkingPolicy}. Pure orchestration over a {@link FederatedIdentityStore} seam
 * so it is fully unit-testable; the live store talks to the subscriber over AMQP.
 *
 * Resolution order:
 * <ol>
 *   <li>existing federated link → that user (returning login);</li>
 *   <li>verified-email match to an existing local user → link + that user;</li>
 *   <li>JIT-provision a new local user (if enabled) → link + the new user;</li>
 *   <li>otherwise rejected.</li>
 * </ol>
 * An <b>unverified</b> email is never used to link to an existing account (account-takeover guard).
 */
public class IdentityBroker {

    private static final Logger LOG = LogManager.getLogger(IdentityBroker.class);

    private final FederatedIdentityStore store;
    private final AttributeMapper attributeMapper;

    public IdentityBroker(final FederatedIdentityStore store, final AttributeMapper attributeMapper) {
        this.store = store;
        this.attributeMapper = attributeMapper;
    }

    /** Security review H5: never auto-link an identity to a local administrator. */
    private java.util.function.BiPredicate<String, String> isAdmin = (realm, userId) -> false;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setPrincipalGuard(final io.helixiam.authorization.service.adminrbac.PrivilegedPrincipalGuard guard) {
        this.isAdmin = guard::isAdmin;
    }

    /** Round 6: how the link of (alias, subject) was made; unknown means {@code AUTO}. */
    private java.util.function.BiFunction<String, String, java.util.Optional<String>> provenance =
            (alias, subject) -> java.util.Optional.empty();

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setLinkService(final io.helixiam.authorization.service.federation.FederatedLinkService links) {
        this.provenance = links::provenance;
    }

    /** Round 6: where refused administrator sign-ins are audited, and how a user id reads as a name. */
    private java.util.function.Consumer<io.helixiam.authorization.security.audit.AuditEvent> audit = e -> { };
    private java.util.function.Function<String, String> usernames = id -> null;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setAuditLog(final io.helixiam.authorization.security.audit.AuditLog auditLog) {
        this.audit = auditLog::emit;
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setUsers(final io.helixiam.authorization.repository.UserCredentialsRepository users) {
        this.usernames = id -> users.findById(id).map(u -> u.getUsername())
                .orElse(null);
    }

    /** Tests: capture audit events. */
    void setAudit(final java.util.function.Consumer<io.helixiam.authorization.security.audit.AuditEvent> audit) {
        this.audit = audit;
    }

    private void refused(final String realm, final String alias, final String userId, final String reason) {
        try {
            final java.util.Map<String, String> detail = new java.util.LinkedHashMap<>();
            detail.put("idpAlias", alias);
            detail.put("userId", userId);
            final String name = usernames.apply(userId);
            if (name != null) {
                detail.put("username", name);
            }
            detail.put("reason", reason);
            audit.accept(io.helixiam.authorization.security.audit.AuditEvent.authn(
                    io.helixiam.authorization.security.audit.AuditContext.nowIso(), "PRIVILEGED_LINK_REFUSED", realm,
                    userId, null, "FAILURE", detail));
        } catch (final RuntimeException e) {
            LOG.debug("Could not audit a refused federated sign-in: {}", e.getClass().getSimpleName());
        }
    }

    /** Tests: the provenance lookup. */
    void setProvenance(final java.util.function.BiFunction<String, String, java.util.Optional<String>> provenance) {
        this.provenance = provenance;
    }

    /** Tests: who counts as an administrator (realm, userId). */
    void setAdminCheck(final java.util.function.BiPredicate<String, String> isAdmin) {
        this.isAdmin = isAdmin;
    }

    public BrokerResult broker(final BrokeredIdentity identity, final AccountLinkingPolicy policy) {
        return broker(identity, policy, null);
    }

    /**
     * Broker an identity, additionally applying the provider's configured attribute/claim mappers (B5).
     *
     * @param mapperConfig the per-IdP {@code "source=target,…"} mapper CSV (may be null/blank); applied on
     *                     top of the default normalization at JIT provisioning, overriding on conflict.
     */
    public BrokerResult broker(final BrokeredIdentity identity, final AccountLinkingPolicy policy,
                               final String mapperConfig) {
        final String alias = identity.idpAlias();
        final String subject = identity.externalSubject();

        // 1. Returning identity: an existing link wins outright.
        final var linked = store.findLinkedUser(alias, subject);
        if (linked.isPresent()) {
            final String realm = io.helixiam.authorization.security.realm.RealmContextHolder.get() == null
                    ? "master" : io.helixiam.authorization.security.realm.RealmContextHolder.get();
            if (isAdmin.test(realm, linked.get()) && !io.helixiam.authorization.domain.federation.LinkProvenance
                    .mayAuthenticateAdmin(provenance.apply(alias, subject).orElse(null))) {
                // Round 6: an administrator signs in through a link only if they made it themselves, a realm admin
                // confirmed it, or it predates the upgrade.
                LOG.warn("Refusing federated sign-in {}:{} to an administrator: the link was made by matching an "
                        + "e-mail address. The administrator links the provider from the account console "
                        + "(Connected accounts, after signing in again) or a realm admin confirms the link.",
                        alias, subject);
                refused(realm, alias, linked.get(), "untrusted-link");
                return BrokerResult.unresolved();
            }
            return BrokerResult.existingLink(linked.get());
        }

        // 2. Link to an existing local user — ONLY on a verified email (never unverified: takeover).
        if (policy.linkByVerifiedEmail() && identity.emailVerified()
                && identity.email() != null && !identity.email().isBlank()) {
            final var existing = store.findUserByEmail(identity.email());
            final String realm = io.helixiam.authorization.security.realm.RealmContextHolder.get() == null
                    ? "master" : io.helixiam.authorization.security.realm.RealmContextHolder.get();
            if (existing.isPresent() && isAdmin.test(realm, existing.get())) {
                // H5: an e-mail address controlled at an external IdP must never take over an administrator. The
                // admin links the identity from the account console while signed in.
                LOG.warn("Not linking federated identity {}:{} to an administrator by e-mail. The administrator "
                        + "links the provider from the account console (Connected accounts, after signing in again), "
                        + "or a realm admin confirms the link.", alias, subject);
                refused(realm, alias, existing.get(), "email-match");
                return BrokerResult.unresolved();
            }
            if (existing.isPresent()) {
                store.link(alias, subject, existing.get(),
                        io.helixiam.authorization.domain.federation.LinkProvenance.AUTO);
                LOG.info("Linked federated identity {}:{} to existing user {} by verified email",
                        alias, subject, existing.get());
                return BrokerResult.linkedExisting(existing.get());
            }
        }

        // 3. Just-in-time provision a new local user.
        if (policy.jitProvision()) {
            // Default normalization first, then the admin-configured per-IdP mappers (B5) override on conflict.
            final java.util.Map<String, String> attributes = new java.util.HashMap<>(attributeMapper.map(identity));
            attributes.putAll(AttributeMapperRules.apply(identity, mapperConfig));
            final String userId = store.provisionUser(identity, attributes);
            store.link(alias, subject, userId, io.helixiam.authorization.domain.federation.LinkProvenance.JIT);
            LOG.info("JIT-provisioned user {} for federated identity {}:{}", userId, alias, subject);
            return BrokerResult.provisioned(userId);
        }

        // 4. No match and JIT disabled → rejected.
        LOG.warn("Rejected federated identity {}:{} — no link/match and JIT provisioning disabled", alias, subject);
        return BrokerResult.unresolved();
    }
}
