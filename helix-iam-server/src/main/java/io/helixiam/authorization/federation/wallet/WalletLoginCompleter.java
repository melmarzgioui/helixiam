/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserAdminRef;
import io.helixiam.authorization.federation.AccountLinkingPolicy;
import io.helixiam.authorization.federation.AttributeMapperRules;
import io.helixiam.authorization.federation.FederatedIdentityStore;
import io.helixiam.authorization.federation.FederatedLoginCompleter;
import io.helixiam.authorization.federation.spi.AttributeMapper;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Task 18: the wallet-aware end of a wallet login, after the broker callback redeemed the response code
 * ({@link WalletIdentityProvider#redeem}). It replaces {@code IdentityBroker} for wallets and acts on the account
 * decision the response endpoint stored ({@link WalletLinkService#decide}, made when the presentation was verified):
 *
 * <ul>
 *   <li>{@link WalletLinkService.Decision.Existing}: sign in as that user through the shared
 *       {@link FederatedLoginCompleter} (post-broker flow and step-up included). An upgrade link is handed over as the
 *       login's pending commit, so {@link WalletPendingLinkCommit} records it only once the login has succeeded.</li>
 *   <li>{@link WalletLinkService.Decision.Provision}: only when the realm's {@link AccountLinkingPolicy} still allows
 *       just-in-time provisioning. Creates the user (the same conservative JIT user and attribute mapping as every
 *       brokered login, the admin's per-provider mappers on top) and links the number <em>insert-if-absent</em>
 *       ({@link WalletLinkService#link}). If another login linked the same number in the meantime, the number wins:
 *       this login signs in as that owner and the account just created is deleted, so no orphan is left. (With the
 *       default username, the subject, the concurrent insert already fails on the realm's unique username; then
 *       nothing was created and the login signs in as the account the other login linked.)</li>
 *   <li>{@link WalletLinkService.Decision.Refused}: the "link your wallet" explanation
 *       ({@code /broker/<alias>/wallet/link?reason=...}).</li>
 * </ul>
 * A wallet identity is never linked by email and never through {@code FederatedIdentityStore.link} (which overwrites).
 */
@Component
public class WalletLoginCompleter {

    private static final Logger LOG = LogManager.getLogger(WalletLoginCompleter.class);
    private static final String LOGIN_ERROR = "redirect:/login?error=federation";

    private final FederatedIdentityStore store;
    private final AttributeMapper attributeMapper;
    private final AccountLinkingPolicy policy;
    private final WalletLinkService links;
    private final UserAdminPublisher users;
    private final FederatedLoginCompleter completer;

    public WalletLoginCompleter(final FederatedIdentityStore store, final AttributeMapper attributeMapper,
                                final AccountLinkingPolicy policy, final WalletLinkService links,
                                final UserAdminPublisher users, final FederatedLoginCompleter completer) {
        this.store = store;
        this.attributeMapper = attributeMapper;
        this.policy = policy;
        this.links = links;
        this.users = users;
        this.completer = completer;
    }

    /**
     * Completes the redeemed wallet login {@code login} of provider {@code alias} in the current realm; returns the
     * view (a redirect).
     *
     * @param mapperConfig the provider's admin-configured {@code mappers} CSV (may be null)
     */
    public String complete(final String alias, final VerifiedIdentityJson.StoredLogin login, final String mapperConfig,
                           final HttpServletRequest request, final HttpServletResponse response) {
        final String realm = RealmContextHolder.get();
        return switch (login.decision()) {
            case WalletLinkService.Decision.Existing existing ->
                    completer.complete(existing.userId(), login.identity().levelOfAssurance(), request, response,
                            existing.pendingNumberLink());
            case WalletLinkService.Decision.Provision provision -> provision(realm, alias, login.identity(),
                    mapperConfig, request, response);
            case WalletLinkService.Decision.Refused refused -> linkPage(alias, refused.reason());
        };
    }

    private String provision(final String realm, final String alias, final BrokeredIdentity identity,
                             final String mapperConfig, final HttpServletRequest request,
                             final HttpServletResponse response) {
        if (!policy.jitProvision()) {
            // the policy changed since the presentation was verified
            return linkPage(alias, WalletSubject.Reason.LINK_REQUIRED);
        }
        final WalletSubject.AdminNumber subject = new WalletSubject.AdminNumber(identity.externalSubject(), null);
        final Map<String, String> attributes = new HashMap<>(attributeMapper.map(identity));
        attributes.putAll(AttributeMapperRules.apply(identity, mapperConfig));
        final String created;
        try {
            created = store.provisionUser(identity, attributes);
        } catch (final RuntimeException e) {
            // The default username is the subject itself (unique per realm), so a concurrent login that provisioned
            // the same number first makes this insert fail: sign in as the account it linked, nothing was created.
            LOG.info("wallet: provisioning failed ({}), looking for a concurrent login's account in realm {}",
                    e.getClass().getSimpleName(), LogSafe.sanitize(realm));
            return links.find(realm, alias, subject)
                    .map(userId -> completer.complete(userId, identity.levelOfAssurance(), request, response, null))
                    .orElse(LOGIN_ERROR);
        }
        final WalletLinkService.LinkResult linked = links.link(realm, created, alias, subject);
        if (linked != WalletLinkService.LinkResult.LINKED_TO_ANOTHER_USER) {
            LOG.info("wallet: provisioned user {} in realm {} for provider {}", LogSafe.sanitize(created),
                    LogSafe.sanitize(realm), LogSafe.sanitize(alias));
            return completer.complete(created, identity.levelOfAssurance(), request, response, null);
        }
        // Lost the race: another login linked this number first. The number wins; remove the fresh account.
        final Optional<String> owner = links.find(realm, alias, subject);
        users.delete(new UserAdminRef(realm, created));
        LOG.info("wallet: number already linked by a concurrent login; removed the fresh user {} in realm {}",
                LogSafe.sanitize(created), LogSafe.sanitize(realm));
        return owner.map(userId -> completer.complete(userId, identity.levelOfAssurance(), request, response, null))
                .orElse(LOGIN_ERROR);
    }

    private static String linkPage(final String alias, final WalletSubject.Reason reason) {
        return "redirect:/broker/" + org.springframework.web.util.UriUtils.encodePathSegment(alias,
                java.nio.charset.StandardCharsets.UTF_8) + "/wallet/link?reason="
                + reason.name().toLowerCase(Locale.ROOT);
    }
}
