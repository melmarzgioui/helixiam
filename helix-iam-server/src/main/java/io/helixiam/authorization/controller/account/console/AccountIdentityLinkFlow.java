/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import io.helixiam.authorization.amqp.federation.FederatedLinkClaimResult;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.domain.federation.LinkProvenance;
import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.spi.IdpMetadata;
import io.helixiam.authorization.service.account.AccountAudit;
import io.helixiam.authorization.service.federation.FederatedIdentityService;
import io.helixiam.authorization.service.federation.FederatedLinkService;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.io.Serial;
import java.io.Serializable;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Round 6: linking an external identity provider from the account console ({@code created_via = SELF}).
 *
 * <ol>
 *   <li>The signed-in user asks to link a provider ({@code POST /account/identities/link}, CSRF-protected). The
 *       console's step-up comes first: the session must have signed in within the {@code max_age} window
 *       ({@link io.helixiam.authorization.service.account.AccountStepUp}), else the user signs in again.</li>
 *   <li>{@link #begin} stores a <b>link intent</b> in this session: the user, the provider and a random token, valid
 *       for ten minutes. The browser goes to the broker with the token.</li>
 *   <li>The broker binds the intent to the login {@code state} it mints ({@link #bindState}), so only the callback of
 *       that very login can complete it.</li>
 *   <li>At the callback ({@link #complete}), after the provider validated the response, the intent is consumed and
 *       the external identity is linked to the user, but only if the session still belongs to that user and the identity
 *       is not linked to someone else. It is never a sign-in.</li>
 * </ol>
 */
@Component
public class AccountIdentityLinkFlow {

    private static final Logger LOG = LogManager.getLogger(AccountIdentityLinkFlow.class);
    private static final String INTENT_ATTR = "HELIX_ACCOUNT_LINK_INTENT";
    private static final long TTL_MILLIS = 10 * 60 * 1000L;
    private static final Set<IdpMetadata.Protocol> LINKABLE =
            EnumSet.of(IdpMetadata.Protocol.OIDC, IdpMetadata.Protocol.SAML2, IdpMetadata.Protocol.SOCIAL);

    /** What the user asked for, bound to this session. Serializable: sessions may live in Redis. */
    public record Intent(String realm, String userId, String alias, String token, long expiresAt, String state)
            implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;

        Intent withState(final String value) {
            return new Intent(realm, userId, alias, token, expiresAt, value);
        }
    }

    /** The outcome of a link, shown in the console ({@code account.identities.status/error.*}). */
    public enum Outcome { LINKED, ALREADY_LINKED, TAKEN, REFUSED }

    /** One provider of the realm the user can link, for the console. */
    public record Row(String alias, String displayName, boolean linked) {
    }

    private final IdentityProviderRegistry registry;
    private final FederatedIdentityService identities;
    private final FederatedLinkService links;
    private final AccountAudit audit;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    @org.springframework.beans.factory.annotation.Autowired
    public AccountIdentityLinkFlow(final IdentityProviderRegistry registry, final FederatedIdentityService identities,
                                   final FederatedLinkService links, final AccountAudit audit) {
        this(registry, identities, links, audit, Clock.systemUTC());
    }

    AccountIdentityLinkFlow(final IdentityProviderRegistry registry, final FederatedIdentityService identities,
                            final FederatedLinkService links, final AccountAudit audit, final Clock clock) {
        this.registry = registry;
        this.identities = identities;
        this.links = links;
        this.audit = audit;
        this.clock = clock;
    }

    /** The realm's providers a user can link here (sign-in capable OIDC, SAML and social; wallets have their own). */
    public List<Row> rows(final String realm, final String userId) {
        final Set<String> linked = userId == null ? Set.of() : links.linksOf(userId).stream()
                .map(l -> l.getIdpAlias()).filter(Objects::nonNull).collect(Collectors.toSet());
        return registry.signInMetadatas(realm).stream().filter(m -> LINKABLE.contains(m.protocol()))
                .map(m -> new Row(m.alias(), m.displayName() == null ? m.alias() : m.displayName(),
                        linked.contains(m.alias()))).toList();
    }

    /** Whether {@code alias} is a provider of {@code realm} the user can link here. */
    public boolean linkable(final String realm, final String alias) {
        if (realm == null || alias == null || alias.isBlank()) {
            return false;
        }
        try {
            final IdentityProvider provider = registry.get(realm, alias);
            return provider.signInCapable() && LINKABLE.contains(provider.metadata().protocol());
        } catch (final IllegalArgumentException e) {
            return false;
        }
    }

    private static final String PENDING_ATTR = "HELIX_ACCOUNT_LINK_PENDING";

    /** Remembers which provider this session asked to link, across the step-up sign-in. */
    public void remember(final HttpSession session, final String alias) {
        session.setAttribute(PENDING_ATTR, alias);
    }

    /** The provider this session asked to link (consumed), if any. */
    public Optional<String> takePending(final HttpSession session) {
        final String alias = session.getAttribute(PENDING_ATTR) instanceof String a ? a : null;
        session.removeAttribute(PENDING_ATTR);
        return Optional.ofNullable(alias);
    }

    /** Where the browser goes to link {@code alias} now: the broker in link mode, with a fresh intent. */
    public String brokerPath(final HttpSession session, final String realm, final String userId, final String alias) {
        return "/broker/" + java.net.URLEncoder.encode(alias, java.nio.charset.StandardCharsets.UTF_8) + "?link="
                + begin(session, realm, userId, alias);
    }

    /** Stores a fresh intent for {@code userId} and {@code alias}; returns the token the broker start carries. */
    public String begin(final HttpSession session, final String realm, final String userId, final String alias) {
        final byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        final String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        session.setAttribute(INTENT_ATTR, new Intent(realm, userId, alias, token, clock.millis() + TTL_MILLIS, null));
        return token;
    }

    /**
     * At the broker start: binds this session's intent to the login {@code state}, when {@code token} is the intent's,
     * for this realm and provider, unexpired and of the signed-in user. False otherwise (the intent is dropped).
     */
    public boolean bindState(final HttpSession session, final String realm, final String alias, final String token,
                             final String state) {
        final Intent intent = session.getAttribute(INTENT_ATTR) instanceof Intent i ? i : null;
        if (intent == null || token == null || !token.equals(intent.token()) || !alias.equals(intent.alias())
                || !Objects.equals(realm, intent.realm()) || clock.millis() > intent.expiresAt()
                || !intent.userId().equals(currentUserId().orElse(null))) {
            session.removeAttribute(INTENT_ATTR);
            return false;
        }
        session.setAttribute(INTENT_ATTR, intent.withState(state));
        return true;
    }

    /** At the callback: the intent bound to this login's {@code state}, consumed; empty for an ordinary sign-in. */
    public Optional<Intent> take(final HttpSession session, final String alias, final String expectedState) {
        final Intent intent = session.getAttribute(INTENT_ATTR) instanceof Intent i ? i : null;
        if (intent == null || intent.state() == null || expectedState == null || !intent.state().equals(expectedState)
                || !alias.equals(intent.alias())) {
            return Optional.empty();
        }
        session.removeAttribute(INTENT_ATTR);
        return Optional.of(intent);
    }

    /** Links the validated {@code identity} to the intent's user (SELF); refuses a foreign or stale session. */
    public Outcome complete(final Intent intent, final BrokeredIdentity identity, final HttpServletRequest request) {
        final Optional<String> current = currentUserId();
        Outcome outcome;
        if (clock.millis() > intent.expiresAt() || current.isEmpty() || !current.get().equals(intent.userId())) {
            outcome = Outcome.REFUSED;
        } else {
            final FederatedLinkClaimResult claimed = identities.claimLink(intent.realm(), intent.alias(),
                    identity.externalSubject(), intent.userId(), LinkProvenance.SELF);
            outcome = switch (claimed == null || claimed.status() == null
                    ? FederatedLinkClaimResult.Status.USER_NOT_IN_REALM : claimed.status()) {
                case CREATED -> Outcome.LINKED;
                case ALREADY_LINKED -> {
                    // The user proved control of an identity already linked to them: it now counts as self-made.
                    links.link(intent.alias(), identity.externalSubject(), intent.userId(), LinkProvenance.SELF);
                    yield Outcome.ALREADY_LINKED;
                }
                case LINKED_TO_ANOTHER_USER -> Outcome.TAKEN;
                default -> Outcome.REFUSED;
            };
        }
        LOG.info("Account: link of provider {} for user {} -> {}", LogSafe.sanitize(intent.alias()),
                LogSafe.sanitize(intent.userId()), outcome);
        audit.emit(request, "ACCOUNT_IDENTITY_LINK", intent.realm(), currentUsername().orElse(null), intent.userId(),
                outcome == Outcome.LINKED || outcome == Outcome.ALREADY_LINKED ? AccountAudit.SUCCESS
                        : AccountAudit.FAILURE,
                Map.of("idpAlias", intent.alias(), "result", outcome.name().toLowerCase(java.util.Locale.ROOT)));
        return outcome;
    }

    private static Optional<String> currentUserId() {
        final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.getPrincipal() instanceof UserCredentials u ? Optional.ofNullable(u.getUserId())
                : Optional.empty();
    }

    private static Optional<String> currentUsername() {
        final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.getPrincipal() instanceof UserCredentials u ? Optional.ofNullable(u.getUsername())
                : Optional.empty();
    }
}
