/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.domain.tenant.TenantUser;
import io.helixiam.authorization.federation.AccountLinkingPolicy;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import io.helixiam.authorization.service.federation.FederatedLinkService;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.Objects;
import java.util.Optional;

/**
 * Wallet account linking (maintainer decision 1, spec §8.2) on the EXISTING federated-link mechanism: a wallet link is
 * a {@code federated_link} row {@code (idp_alias, external_subject) → user_id} ({@link FederatedLinkService}), exactly
 * like an OIDC/SAML/eID link, so the account console's "Connected accounts" and the GDPR export see it too. The
 * external subject is the {@link WalletSubject} HMAC (never the number or the attributes), so a link stores no PID
 * data.
 *
 * <h2>Linking</h2>
 * {@link #link} is for an <em>authenticated</em> user: this service takes the user id, the caller (Task 21b's account
 * console controller) enforces the authentication. It is insert-if-absent: re-linking the same user is a no-op
 * ({@link LinkResult#ALREADY_LINKED}); a subject already linked to a different user is refused
 * ({@link LinkResult#LINKED_TO_ANOTHER_USER}) and the existing link stays, also under concurrent attempts. The user
 * must belong to the realm.
 *
 * <h2>Realm scoping</h2>
 * The link table has no realm column (aliases are global, constraints #6). Realm separation comes from the subject,
 * which is keyed by the realm's own pepper, and from {@link #find} only answering with a user of that realm.
 *
 * <h2>Account decision</h2>
 * {@link #decide} is the "administrative number, else link" rule for a wallet sign-in: a linked subject signs in as
 * its user; an unlinked {@link WalletSubject.AdminNumber} may be JIT-provisioned when the realm's
 * {@link AccountLinkingPolicy#jitProvision()} allows (the same policy every brokered login uses; the caller provisions
 * and then links); an unlinked {@link WalletSubject.Tuple} is ALWAYS {@link WalletSubject.Reason#LINK_REQUIRED}: the
 * tuple never creates an account and is never matched against names or email.
 */
@Component
public class WalletLinkService {

    private static final Logger LOG = LogManager.getLogger(WalletLinkService.class);

    private final FederatedLinkService links;
    private final UserCredentialsRepository users;
    private final TenantUserRepository memberships;

    public WalletLinkService(final FederatedLinkService links, final UserCredentialsRepository users,
                             final TenantUserRepository memberships) {
        this.links = links;
        this.users = users;
        this.memberships = memberships;
    }

    /** The outcome of {@link #link}. */
    public enum LinkResult {
        /** The subject is now linked to the user. */
        LINKED,
        /** The subject was already linked to this user; nothing changed. */
        ALREADY_LINKED,
        /** The subject is linked to a different user; nothing changed. */
        LINKED_TO_ANOTHER_USER
    }

    /** The account a wallet sign-in resolves to; see the class javadoc. */
    public sealed interface Decision {

        /** Sign in as the linked user. */
        record Existing(String userId) implements Decision {
        }

        /** No link, administrative number, JIT allowed: the caller provisions a user and links the subject. */
        record Provision() implements Decision {
        }

        /** No sign-in; show the link page with {@code reason}. */
        record Refused(WalletSubject.Reason reason) implements Decision {
            public WalletErrorCode errorCode() {
                return WalletErrorCode.SUBJECT_UNAVAILABLE;
            }
        }
    }

    /**
     * Link {@code subject} to the authenticated {@code userId} for the wallet provider {@code alias}.
     *
     * @throws IllegalArgumentException when the subject is {@link WalletSubject.Unavailable}, or the user does not
     *                                  exist in {@code realmId}
     */
    public LinkResult link(final String realmId, final String userId, final String alias, final WalletSubject subject) {
        final String value = subjectValue(subject)
                .orElseThrow(() -> new IllegalArgumentException("There is no wallet subject to link"));
        requireText(alias, "alias");
        if (!inRealm(realmId, userId)) {
            throw new IllegalArgumentException("The user does not belong to this realm");
        }
        final FederatedLinkService.LinkIfAbsent outcome = links.linkIfAbsent(alias, value, userId);
        final LinkResult result = !userId.equals(outcome.ownerUserId()) ? LinkResult.LINKED_TO_ANOTHER_USER
                : outcome.created() ? LinkResult.LINKED : LinkResult.ALREADY_LINKED;
        LOG.info("wallet: link realm={} alias={} user={} subject={} result={}", LogSafe.sanitize(realmId),
                LogSafe.sanitize(alias), LogSafe.sanitize(userId), value, result);
        return result;
    }

    /** The user of {@code realmId} linked to {@code subject} for {@code alias}, if any. */
    public Optional<String> find(final String realmId, final String alias, final WalletSubject subject) {
        requireText(alias, "alias");
        return subjectValue(subject).flatMap(value -> links.findLinkedUser(alias, value))
                .filter(userId -> inRealm(realmId, userId));
    }

    /** Remove every wallet link {@code userId} has for {@code alias}; returns how many were removed. */
    public int unlink(final String realmId, final String userId, final String alias) {
        requireText(alias, "alias");
        if (!inRealm(realmId, userId)) {
            return 0;
        }
        final int removed = links.unlinkAll(userId, alias);
        LOG.info("wallet: unlink realm={} alias={} user={} removed={}", LogSafe.sanitize(realmId),
                LogSafe.sanitize(alias), LogSafe.sanitize(userId), removed);
        return removed;
    }

    /** The account decision for a wallet sign-in; see the class javadoc. */
    public Decision decide(final String realmId, final String alias, final WalletSubject subject,
                           final AccountLinkingPolicy policy) {
        Objects.requireNonNull(policy, "policy");
        if (subject instanceof WalletSubject.Unavailable unavailable) {
            return new Decision.Refused(unavailable.reason());
        }
        final Optional<String> linked = find(realmId, alias, subject);
        if (linked.isPresent()) {
            return new Decision.Existing(linked.get());
        }
        if (subject instanceof WalletSubject.AdminNumber && policy.jitProvision()) {
            return new Decision.Provision();
        }
        return new Decision.Refused(WalletSubject.Reason.LINK_REQUIRED);
    }

    // ------------------------------------------------------------------------------------------- helpers

    private static Optional<String> subjectValue(final WalletSubject subject) {
        Objects.requireNonNull(subject, "subject");
        return switch (subject) {
            case WalletSubject.AdminNumber a -> Optional.of(a.value());
            case WalletSubject.Tuple t -> Optional.of(t.value());
            case WalletSubject.Unavailable u -> Optional.empty();
        };
    }

    /** The user exists and belongs to {@code realmId} (its own realm, or a realm membership). */
    private boolean inRealm(final String realmId, final String userId) {
        if (realmId == null || realmId.isBlank() || userId == null || userId.isBlank()) {
            return false;
        }
        return users.findByUserId(userId)
                .map(user -> realmId.equals(user.getRealmId()) || memberships.findAllByUserId(userId).stream()
                        .map(TenantUser::getTenantId).anyMatch(realmId::equals))
                .orElse(false);
    }

    private static void requireText(final String value, final String what) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("A " + what + " is required");
        }
    }
}
