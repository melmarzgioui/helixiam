/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.amqp.federation.FederatedIdentityPublisher;
import io.helixiam.authorization.amqp.federation.FederatedLinkClaimResult;
import io.helixiam.authorization.amqp.federation.RealmFederatedLink;
import io.helixiam.authorization.amqp.federation.RealmFederatedLinkLookup;
import io.helixiam.authorization.amqp.federation.RealmFederatedUnlink;
import io.helixiam.authorization.federation.AccountLinkingPolicy;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.Objects;
import java.util.Optional;

/**
 * Wallet account linking (maintainer decision 1, spec §8.2) on the EXISTING federated-link mechanism: a wallet link is
 * a {@code federated_link} row {@code (idp_alias, external_subject) → user_id}, exactly like an OIDC/SAML/eID link, so
 * the account console's "Connected accounts" and the GDPR export see it too. The external subject is the
 * {@link WalletSubject} HMAC (never the number or the attributes), so a link stores no PID data. Every read and write
 * goes through the {@link FederatedIdentityPublisher} seam (the broker's way onto the identity domain, which the
 * subscriber owns), so this works where the publisher has no JDBC.
 *
 * <h2>Linking</h2>
 * {@link #link} is for an <em>authenticated</em> user: this service takes the user id, the caller (Task 21b's account
 * console controller) enforces the authentication. It claims the subject: re-linking the same user is a no-op
 * ({@link LinkResult#ALREADY_LINKED}); a subject linked to a different live user of the realm is refused
 * ({@link LinkResult#LINKED_TO_ANOTHER_USER}) and that link stays, also under concurrent attempts. The user must belong
 * to the realm. Only the administrative-number value is linked for an {@link WalletSubject.AdminNumber}.
 *
 * <h2>Stale links</h2>
 * {@code federated_link} has no foreign key to users, so deleting a user leaves its rows. A link whose owner no longer
 * exists in the realm (deleted, or belonging to another realm) is FREE: {@link #find} treats it as absent and
 * {@link #link} replaces it atomically (delete that row only while it still names that owner, then insert-if-absent,
 * in one transaction), so JIT provisioning followed by linking, and account-console relinking, both work.
 *
 * <h2>Realm scoping</h2>
 * The link table has no realm column (aliases are global, constraints #6). Realm separation comes from the subject,
 * which is keyed by the realm's own pepper, and from {@link #find} only answering with a live user of that realm.
 *
 * <h2>Account decision</h2>
 * {@link #decide} is the "administrative number, else link" rule for a wallet sign-in:
 * <ol>
 *   <li>a linked subject signs in as its user (for an {@link WalletSubject.AdminNumber}, the number's link wins over
 *       any tuple link: it is the stronger subject);</li>
 *   <li><b>upgrade path</b>: an unlinked number whose {@link WalletSubject.AdminNumber#tupleValue() tuple} is linked
 *       signs in as the tuple's user; the number link for that user is returned as a {@link PendingLink}, which the
 *       caller records with {@link #commitPendingLink} only after the whole login succeeded ({@code decide} never
 *       writes). The tuple value exists only when the provider acknowledges the weak subject, so with the flag off the
 *       tuple is never consulted;</li>
 *   <li>an unlinked number may be JIT-provisioned when the realm's {@link AccountLinkingPolicy#jitProvision()} allows
 *       (the same policy every brokered login uses; the caller provisions and then calls {@link #link});</li>
 *   <li>an unlinked {@link WalletSubject.Tuple} is ALWAYS {@link WalletSubject.Reason#LINK_REQUIRED}: the tuple never
 *       creates an account and is never matched against names or email.</li>
 * </ol>
 */
@Component
public class WalletLinkService {

    private static final Logger LOG = LogManager.getLogger(WalletLinkService.class);

    private final FederatedIdentityPublisher identities;

    public WalletLinkService(final FederatedIdentityPublisher identities) {
        this.identities = identities;
    }

    /** The outcome of {@link #link}. */
    public enum LinkResult {
        /** The subject is now linked to the user (also when it replaced a stale link). */
        LINKED,
        /** The subject was already linked to this user; nothing changed. */
        ALREADY_LINKED,
        /** The subject is linked to a different live user; nothing changed. */
        LINKED_TO_ANOTHER_USER
    }

    /**
     * The administrative-number link the upgrade path wants: {@code subject} (the number's HMAC) for {@code userId},
     * the user the tuple matched. {@link #decide} only returns it; {@link #commitPendingLink} records it.
     */
    public record PendingLink(String realmId, String alias, String subject, String userId) {
    }

    /**
     * Records a {@link Decision.Existing#pendingNumberLink()}. The caller (Task 18) invokes it ONLY after the whole
     * login has succeeded (post-broker flow, MFA, minimum LoA, policy): a weak tuple match must never turn into a
     * permanent number→account link for a login that then fails, because the number link wins over the tuple from
     * then on, even after an admin turns {@code acknowledgeWeakSubject} off.
     *
     * <p>It claims the number like {@link #link} does (race-safe, never overwrites a live link, replaces a stale one)
     * and returns the number's owner afterwards. That is {@code pending.userId()}, unless another user claimed the
     * number between {@link #decide} and this call: then it returns THAT user (the number wins), and the caller must
     * not complete the login as {@code pending.userId()} (e.g. restart it or refuse it). Empty when
     * {@code pending.userId()} no longer exists in the realm. Idempotent.
     */
    public Optional<String> commitPendingLink(final PendingLink pending) {
        Objects.requireNonNull(pending, "pending");
        requireText(pending.alias(), "alias");
        if (pending.realmId() == null || pending.realmId().isBlank() || pending.userId() == null
                || pending.userId().isBlank()) {
            return Optional.empty();
        }
        final FederatedLinkClaimResult claimed = identities.claimLink(
                new RealmFederatedLink(pending.realmId(), pending.alias(), pending.subject(), pending.userId()));
        if (claimed == null || claimed.status() == null
                || claimed.status() == FederatedLinkClaimResult.Status.USER_NOT_IN_REALM) {
            return Optional.empty();
        }
        LOG.info("wallet: committed number link, realm={} alias={} user={} subject={} status={}",
                LogSafe.sanitize(pending.realmId()), LogSafe.sanitize(pending.alias()),
                LogSafe.sanitize(claimed.ownerUserId()), pending.subject(), claimed.status());
        return Optional.ofNullable(claimed.ownerUserId());
    }

    /** The account a wallet sign-in resolves to; see the class javadoc. */
    public sealed interface Decision {

        /**
         * Sign in as the linked user. {@code pendingNumberLink} is non-null only on the upgrade path: commit it with
         * {@link #commitPendingLink} after the login succeeded.
         */
        record Existing(String userId, PendingLink pendingNumberLink) implements Decision {
            public Existing(final String userId) {
                this(userId, null);
            }
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
        final LinkResult result = claim(realmId, userId, alias, value).orElseThrow(
                () -> new IllegalArgumentException("The user does not belong to this realm"));
        LOG.info("wallet: link realm={} alias={} user={} subject={} result={}", LogSafe.sanitize(realmId),
                LogSafe.sanitize(alias), LogSafe.sanitize(userId), value, result);
        return result;
    }

    /** The live user of {@code realmId} linked to {@code subject} for {@code alias}, if any. */
    public Optional<String> find(final String realmId, final String alias, final WalletSubject subject) {
        requireText(alias, "alias");
        return subjectValue(subject).flatMap(value -> find(realmId, alias, value));
    }

    /** Remove every wallet link {@code userId} has for {@code alias}; returns how many were removed. */
    public int unlink(final String realmId, final String userId, final String alias) {
        requireText(alias, "alias");
        final Integer removed = identities.unlinkAll(new RealmFederatedUnlink(realmId, userId, alias));
        final int count = removed == null ? 0 : removed;
        LOG.info("wallet: unlink realm={} alias={} user={} removed={}", LogSafe.sanitize(realmId),
                LogSafe.sanitize(alias), LogSafe.sanitize(userId), count);
        return count;
    }

    /**
     * The account decision for a wallet sign-in; see the class javadoc. Pure: it only reads links, never writes. On
     * the upgrade path the number link is returned as {@link Decision.Existing#pendingNumberLink()}.
     */
    public Decision decide(final String realmId, final String alias, final WalletSubject subject,
                           final AccountLinkingPolicy policy) {
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(subject, "subject");
        requireText(alias, "alias");
        return switch (subject) {
            case WalletSubject.Unavailable unavailable -> new Decision.Refused(unavailable.reason());
            case WalletSubject.Tuple tuple -> find(realmId, alias, tuple.value())
                    .<Decision>map(Decision.Existing::new)
                    .orElse(new Decision.Refused(WalletSubject.Reason.LINK_REQUIRED));
            case WalletSubject.AdminNumber number -> decideNumber(realmId, alias, number, policy);
        };
    }

    private Decision decideNumber(final String realmId, final String alias, final WalletSubject.AdminNumber number,
                                  final AccountLinkingPolicy policy) {
        final Optional<String> linked = find(realmId, alias, number.value());
        if (linked.isPresent()) {
            return new Decision.Existing(linked.get());
        }
        if (number.tupleValue() != null) {
            final Optional<String> tupleUser = find(realmId, alias, number.tupleValue());
            if (tupleUser.isPresent()) {
                // Pure: the number link is only proposed; the caller commits it after the login succeeded.
                return new Decision.Existing(tupleUser.get(),
                        new PendingLink(realmId, alias, number.value(), tupleUser.get()));
            }
        }
        return policy.jitProvision() ? new Decision.Provision()
                : new Decision.Refused(WalletSubject.Reason.LINK_REQUIRED);
    }

    // ------------------------------------------------------------------------------------------- helpers

    private Optional<String> find(final String realmId, final String alias, final String value) {
        if (realmId == null || realmId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(identities.findRealmLinkedUser(new RealmFederatedLinkLookup(realmId, alias, value)));
    }

    /** The claim outcome, or empty when the user does not exist in the realm. */
    private Optional<LinkResult> claim(final String realmId, final String userId, final String alias,
                                       final String value) {
        if (realmId == null || realmId.isBlank() || userId == null || userId.isBlank()) {
            return Optional.empty();
        }
        final FederatedLinkClaimResult claimed =
                identities.claimLink(new RealmFederatedLink(realmId, alias, value, userId));
        if (claimed == null || claimed.status() == null) {
            throw new IllegalStateException("The wallet link could not be stored");
        }
        return switch (claimed.status()) {
            case CREATED -> Optional.of(LinkResult.LINKED);
            case ALREADY_LINKED -> Optional.of(LinkResult.ALREADY_LINKED);
            case LINKED_TO_ANOTHER_USER -> Optional.of(LinkResult.LINKED_TO_ANOTHER_USER);
            case USER_NOT_IN_REALM -> Optional.empty();
        };
    }

    private static Optional<String> subjectValue(final WalletSubject subject) {
        Objects.requireNonNull(subject, "subject");
        return switch (subject) {
            case WalletSubject.AdminNumber a -> Optional.of(a.value());
            case WalletSubject.Tuple t -> Optional.of(t.value());
            case WalletSubject.Unavailable u -> Optional.empty();
        };
    }

    private static void requireText(final String value, final String what) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("A " + what + " is required");
        }
    }
}
