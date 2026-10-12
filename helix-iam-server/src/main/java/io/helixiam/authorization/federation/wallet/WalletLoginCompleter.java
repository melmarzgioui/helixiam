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
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
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
 *       this login signs in as that owner and the account just created is deleted (audited as {@code USER_DELETE},
 *       reason {@code wallet_jit_race_lost}), so no orphan is left. With the default username (the subject) the
 *       concurrent insert already fails on the realm's unique username ({@link DataIntegrityViolationException},
 *       the only failure taken for a conflict): when the number is linked, the login signs in as that account and
 *       nothing was created; when it is not, a stale unlinked user holds the username, and provisioning is retried
 *       ONCE under {@code <subject>-<16 hex>} (a second conflict, like any other failure, propagates to the broker's
 *       {@code error=federation}, logged at WARN without PII; the stale user is left for an admin).</li>
 *   <li>{@link WalletLinkService.Decision.Refused}: the "link your wallet" explanation
 *       ({@code /broker/<alias>/wallet/link?reason=...}).</li>
 * </ul>
 * A wallet identity is never linked by email and never through {@code FederatedIdentityStore.link} (which overwrites).
 */
@Component
public class WalletLoginCompleter {

    private static final Logger LOG = LogManager.getLogger(WalletLoginCompleter.class);
    private static final String LOGIN_ERROR = "redirect:/login?error=federation";
    /** The audit actor of a user removed by the wallet broker itself (not an admin). */
    static final String AUDIT_ACTOR = "wallet-broker";

    private final FederatedIdentityStore store;
    private final AttributeMapper attributeMapper;
    private final AccountLinkingPolicy policy;
    private final WalletLinkService links;
    private final UserAdminPublisher users;
    private final FederatedLoginCompleter completer;
    private final AuditLog audit;
    private final SecureRandom random = new SecureRandom();

    public WalletLoginCompleter(final FederatedIdentityStore store, final AttributeMapper attributeMapper,
                                final AccountLinkingPolicy policy, final WalletLinkService links,
                                final UserAdminPublisher users, final FederatedLoginCompleter completer,
                                final AuditLog audit) {
        this.store = store;
        this.attributeMapper = attributeMapper;
        this.policy = policy;
        this.links = links;
        this.users = users;
        this.completer = completer;
        this.audit = audit;
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
        String created;
        try {
            created = store.provisionUser(identity, attributes);
        } catch (final DataIntegrityViolationException duplicate) {
            // The default username is the subject itself, unique per realm. Either a concurrent login provisioned this
            // number first (then it is, or is about to be, linked), or a stale unlinked user holds the username.
            final Optional<String> owner = links.find(realm, alias, subject);
            if (owner.isPresent()) {
                LOG.info("wallet: a concurrent login provisioned this number first; signing in as its account, "
                        + "realm={} alias={}", LogSafe.sanitize(realm), LogSafe.sanitize(alias));
                return completer.complete(owner.get(), identity.levelOfAssurance(), request, response, null);
            }
            // A stale user holds the username: provision once more under a suffixed username (no loop: a second
            // conflict propagates to the federation error). The stale user is left for an admin to clean up.
            LOG.warn("wallet: the default username is taken by an unlinked user; provisioning under a suffixed "
                    + "username, realm={} alias={}", LogSafe.sanitize(realm), LogSafe.sanitize(alias));
            final Map<String, String> retry = new HashMap<>(attributes);
            retry.put("username", identity.externalSubject() + "-" + suffix());
            created = store.provisionUser(identity, retry);
        } catch (final RuntimeException e) {
            LOG.warn("wallet: provisioning failed in realm {}: {}", LogSafe.sanitize(realm),
                    e.getClass().getSimpleName());
            throw e;
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
        audit.emit(AuditEvent.admin(AuditContext.nowIso(), "USER_DELETE", realm, AUDIT_ACTOR,
                AuditContext.clientIp(request), "user", created, "SUCCESS", Map.of("reason", "wallet_jit_race_lost",
                        "idpAlias", alias)));
        LOG.info("wallet: number already linked by a concurrent login; removed the fresh user {} in realm {}",
                LogSafe.sanitize(created), LogSafe.sanitize(realm));
        return owner.map(userId -> completer.complete(userId, identity.levelOfAssurance(), request, response, null))
                .orElse(LOGIN_ERROR);
    }

    /** 8 random bytes as 16 lower-case hex characters. */
    private String suffix() {
        final byte[] bytes = new byte[8];
        random.nextBytes(bytes);
        return java.util.HexFormat.of().formatHex(bytes);
    }

    private static String linkPage(final String alias, final WalletSubject.Reason reason) {
        return "redirect:/broker/" + org.springframework.web.util.UriUtils.encodePathSegment(alias,
                java.nio.charset.StandardCharsets.UTF_8) + "/wallet/link?reason="
                + reason.name().toLowerCase(Locale.ROOT);
    }
}
