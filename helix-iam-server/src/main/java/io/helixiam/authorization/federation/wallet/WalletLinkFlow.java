/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.security.flow.BrowserBinding;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

/**
 * Task 21b: the account console's "Link EU Digital Identity Wallet" (maintainer decision 1). The ONLY way a wallet
 * without an administrative number can ever reach an account: a signed-in user, who signed in recently (the caller
 * enforces both), binds their wallet explicitly.
 *
 * <ol>
 *   <li>{@link #start}: a {@link io.helixiam.authorization.federation.wallet.transaction.WalletTransaction.Purpose#LINK}
 *       transaction recording the user server side ({@link WalletIdentityProvider#startLink}), bound to this browser
 *       ({@link BrowserBinding}) with a fresh anti-forgery state kept in the session. The browser goes to the same
 *       wallet page as a login; the wallet answers the same response endpoint, which only resolves the subject (no
 *       login decision, no JIT).</li>
 *   <li>{@link #complete}: the console's callback. The response code is redeemed with this session's state and
 *       binding (single use, constant time; a refusal does not burn it), and the session's user must be the user that
 *       started the link. Then the resolved subject is linked to that user, insert-if-absent
 *       ({@link WalletLinkService#link}): the administrative number, and its attribute tuple too when the provider
 *       accepts the weak subject (so the wallet still signs in should a later PID lack the number); or the tuple alone.
 *       No subject (the provider does not accept the tuple, or the PID lacks data) is refused with its reason.</li>
 * </ol>
 * A subject already linked to another account is refused and stays where it is ({@link Outcome#LINKED_TO_ANOTHER_USER};
 * the caller never says which account). Nobody is ever signed in here, nothing is linked by email or name, and no
 * account is created.
 */
@Component
public class WalletLinkFlow {

    /** Session attribute prefix (plus the alias): this browser's state for its live wallet link. */
    static final String STATE_ATTR = "HELIX_WALLET_LINK_STATE_";
    /** Session attribute prefix (plus the alias): this browser's live link transaction, discarded on a new start. */
    static final String TX_ATTR = "HELIX_WALLET_LINK_TX_";

    private static final Logger LOG = LogManager.getLogger(WalletLinkFlow.class);
    private static final int STATE_BYTES = 32;

    private final WalletLinkService links;
    /** Item 4: emails the "wallet linked" notice after a new link; null sends none (tests of other behaviour). */
    private final WalletLinkedNotice notice;
    private final SecureRandom random = new SecureRandom();

    public WalletLinkFlow(final WalletLinkService links) {
        this(links, null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public WalletLinkFlow(final WalletLinkService links, final WalletLinkedNotice notice) {
        this.links = links;
        this.notice = notice;
    }

    /** How a link ended; the console shows each one. */
    public enum Outcome {
        /** The wallet is now linked to the user. */
        LINKED,
        /** It already was; nothing changed. */
        ALREADY_LINKED,
        /** It belongs to another account; nothing changed (never say which). */
        LINKED_TO_ANOTHER_USER,
        /** No administrative number, and the provider does not link wallets without one. */
        WEAK_SUBJECT_NOT_ACKNOWLEDGED,
        /** The wallet did not share the identity data needed to link it. */
        MISSING_IDENTITY_ATTRIBUTES,
        /** The provider cannot link wallets at all. */
        STRATEGY_NOT_SUPPORTED,
        /** Not this browser's, not this user's, expired, already used, or unknown; nothing linked. */
        REFUSED
    }

    /**
     * Starts a wallet link of {@code userId} (signed in, recently) in {@code realmId}, replacing this browser's earlier
     * link transaction of the provider; returns where to send the browser (realm-relative: the wallet page, or the
     * "busy" page when the transaction store is full).
     */
    public String start(final WalletIdentityProvider provider, final String realmId, final String userId,
                        final HttpSession session) {
        Objects.requireNonNull(session, "session");
        final String alias = provider.config().alias();
        final String txKey = BrowserBinding.sessionKey(TX_ATTR, realmId, alias); // per (realm, alias): item 2
        final String stateKey = BrowserBinding.sessionKey(STATE_ATTR, realmId, alias);
        if (session.getAttribute(txKey) instanceof String previous) {
            provider.transactions().discard(previous);
            session.removeAttribute(txKey);
        }
        final String state = token();
        final String binding = BrowserBinding.begin(session, realmId, alias);
        final IdentityProvider.RedirectResponse redirect = provider.startLink(
                new IdentityProvider.AuthnRequestContext(realmId, state, null, binding), userId);
        session.setAttribute(stateKey, state);
        final Map<String, String> parameters = redirect.parameters();
        if (parameters != null && parameters.get(WalletIdentityProvider.TRANSACTION_PARAM) != null) {
            session.setAttribute(txKey, parameters.get(WalletIdentityProvider.TRANSACTION_PARAM));
        }
        return redirect.location();
    }

    /**
     * The console's callback: redeems {@code responseCode} for this browser and links the wallet to {@code userId} if
     * that is the user who started it. {@code session} may be {@code null} (then nothing matches: refused).
     */
    public Outcome complete(final WalletIdentityProvider provider, final String realmId, final String userId,
                            final String responseCode, final HttpSession session) {
        final String alias = provider.config().alias();
        if (session == null || blank(responseCode) || blank(userId)) {
            return Outcome.REFUSED;
        }
        final String txKey = BrowserBinding.sessionKey(TX_ATTR, realmId, alias);
        final String stateKey = BrowserBinding.sessionKey(STATE_ATTR, realmId, alias);
        final String state = session.getAttribute(stateKey) instanceof String s ? s : null;
        final WalletIdentityProvider.LinkRedemption redeemed;
        try {
            redeemed = provider.redeemLink(new IdentityProvider.CallbackContext(realmId,
                    Map.of(WalletIdentityProvider.RESPONSE_CODE_PARAM, responseCode), state, null, null, null,
                    BrowserBinding.current(session, realmId, alias)));
        } catch (final WalletVerificationException e) {
            LOG.warn("wallet: link callback refused, realm={} alias={} reason={}", LogSafe.sanitize(realmId),
                    LogSafe.sanitize(alias), e.code().reason());
            return Outcome.REFUSED;
        }
        // Redeemed: this browser's link is over, whatever follows.
        session.removeAttribute(stateKey);
        session.removeAttribute(txKey);
        BrowserBinding.clear(session, realmId, alias);
        if (!userId.equals(redeemed.initiatingUserId())) {
            LOG.warn("wallet: link callback refused, the signed-in user did not start it: realm={} alias={} user={}",
                    LogSafe.sanitize(realmId), LogSafe.sanitize(alias), LogSafe.sanitize(userId));
            return Outcome.REFUSED;
        }
        final Outcome outcome = link(realmId, userId, alias, redeemed.subject());
        if (outcome == Outcome.LINKED && notice != null) {
            notice.send(realmId, userId); // item 4: the user learns of a link they may not have made
        }
        return outcome;
    }

    private Outcome link(final String realmId, final String userId, final String alias, final WalletSubject subject) {
        return switch (subject) {
            case WalletSubject.Unavailable unavailable -> switch (unavailable.reason()) {
                case WEAK_SUBJECT_NOT_ACKNOWLEDGED -> Outcome.WEAK_SUBJECT_NOT_ACKNOWLEDGED;
                case MISSING_IDENTITY_ATTRIBUTES -> Outcome.MISSING_IDENTITY_ATTRIBUTES;
                case STRATEGY_NOT_SUPPORTED, LINK_REQUIRED -> Outcome.STRATEGY_NOT_SUPPORTED;
            };
            case WalletSubject.Tuple tuple -> outcome(links.link(realmId, userId, alias, tuple));
            case WalletSubject.AdminNumber number -> {
                final Outcome linked = outcome(links.link(realmId, userId, alias,
                        new WalletSubject.AdminNumber(number.value(), null)));
                if (linked != Outcome.LINKED_TO_ANOTHER_USER && number.tupleValue() != null) {
                    // Best effort: the number is the subject that counts (it wins at sign-in). A tuple already
                    // claimed by another account stays theirs.
                    final WalletLinkService.LinkResult tuple = links.link(realmId, userId, alias,
                            new WalletSubject.Tuple(number.tupleValue()));
                    if (tuple == WalletLinkService.LinkResult.LINKED_TO_ANOTHER_USER) {
                        LOG.warn("wallet: number linked, its tuple belongs to another account: realm={} alias={}",
                                LogSafe.sanitize(realmId), LogSafe.sanitize(alias));
                    }
                }
                yield linked;
            }
        };
    }

    private static Outcome outcome(final WalletLinkService.LinkResult result) {
        return switch (result) {
            case LINKED -> Outcome.LINKED;
            case ALREADY_LINKED -> Outcome.ALREADY_LINKED;
            case LINKED_TO_ANOTHER_USER -> Outcome.LINKED_TO_ANOTHER_USER;
        };
    }

    private String token() {
        final byte[] bytes = new byte[STATE_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static boolean blank(final String value) {
        return value == null || value.isBlank();
    }
}
