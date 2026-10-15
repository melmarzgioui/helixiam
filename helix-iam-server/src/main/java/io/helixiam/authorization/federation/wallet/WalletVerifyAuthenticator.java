/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.Authenticator;
import io.helixiam.authorization.flow.spi.AuthenticatorCategory;
import io.helixiam.authorization.flow.spi.AuthenticatorMetadata;
import io.helixiam.authorization.flow.spi.ConfigProperty;
import io.helixiam.authorization.flow.spi.FactorClass;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.security.flow.BrowserBinding;
import io.helixiam.authorization.security.flow.InFlightClientResolver;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Verify-only / step-up EUDI wallet step ({@code subject.strategy=NONE};
 * docs/superpowers/specs/2026-10-15-wallet-verify-only-design.md). It runs after the user is identified and never
 * identifies anyone itself:
 *
 * <ul>
 *   <li>{@link #authenticate}: no identified user → failure (never a first factor). Else it starts a
 *       {@code VERIFY} transaction of the configured verify-only connection ({@value #PROVIDER_ALIAS}) for that user,
 *       bound to this browser and a fresh state kept on the flow, and challenges: {@code GET /flow} sends the browser
 *       to the wallet page ({@link #REDIRECT_ATTRIBUTE}).</li>
 *   <li>{@link #action} with {@code response_code} (the wallet page's / the wallet's {@code /flow/wallet/callback}):
 *       redeems it (state, binding, single use), then binds the wallet to the user (design D4): the presented
 *       administrative number, when it is linked at the linked login connection, must be linked to THIS user (the number
 *       wins); otherwise the attribute tuple, when the linked connection accepts it, must be. No link → refused. On
 *       success the step asserts the presentation's level of assurance (the login's {@code acr}) and, when the login
 *       completes an authorization request, releases the allow-listed {@code verified_claims}.</li>
 *   <li>{@link #action} without a code ({@code restart}, the "try again" button): challenges again, so the engine
 *       runs {@link #authenticate} afresh (a new transaction; the earlier one is discarded).</li>
 * </ul>
 * Never creates or links an account; every end is audited ({@link WalletVerifyAudit}) without PID values.
 */
@Component
public class WalletVerifyAuthenticator implements Authenticator {

    /** SPI id referenced by flow executions and the console editor. */
    public static final String ID = "eudi-wallet-verify";
    /** Config key: the alias of the realm's verify-only wallet connection. */
    public static final String PROVIDER_ALIAS = "providerAlias";
    /** The challenge view ({@code templates/flow/wallet-verify.html}): what to do, and "try again" after a failure. */
    public static final String VIEW = "wallet-verify";
    /** {@link AuthenticationContext#REDIRECT_ATTRIBUTE}: {@code GET /flow} sends the browser to the wallet page. */
    public static final String REDIRECT_ATTRIBUTE = AuthenticationContext.REDIRECT_ATTRIBUTE;
    /** Form parameter of the "try again" button. */
    public static final String RESTART_PARAM = "restart";

    static final String STATE_ATTRIBUTE = "wallet-verify.state";
    static final String TX_ATTRIBUTE = "wallet-verify.tx";
    private static final Logger LOG = LogManager.getLogger(WalletVerifyAuthenticator.class);
    private static final int STATE_BYTES = 32;
    private static final String TRUST_FRAMEWORK = "eidas";

    private final IdentityProviderRegistry registry;
    private final WalletLinkService links;
    private final AuditLog audit;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    @org.springframework.beans.factory.annotation.Autowired
    public WalletVerifyAuthenticator(final IdentityProviderRegistry registry, final WalletLinkService links,
                                     final AuditLog audit) {
        this(registry, links, audit, Clock.systemUTC());
    }

    WalletVerifyAuthenticator(final IdentityProviderRegistry registry, final WalletLinkService links,
                              final AuditLog audit, final Clock clock) {
        this.registry = registry;
        this.links = links;
        this.audit = audit;
        this.clock = clock;
    }

    @Override
    public AuthenticatorMetadata metadata() {
        return new AuthenticatorMetadata(ID, "EU Digital Identity Wallet verification", FactorClass.POSSESSION, 5,
                AuthenticatorCategory.METHOD,
                List.of(ConfigProperty.string(PROVIDER_ALIAS, "Verify-only wallet connection", true)));
    }

    @Override
    public void authenticate(final AuthenticationContext context) {
        if (context.userId() == null || context.userId().isBlank()) {
            LOG.warn("wallet verify: the step ran before any identity step; refusing (realm={})",
                    LogSafe.sanitize(context.realmId()));
            context.failure("wallet verification needs an identified user");
            return;
        }
        final Optional<WalletIdentityProvider> provider = provider(context);
        final HttpSession session = session();
        if (provider.isEmpty() || session == null) {
            context.failure("wallet verification is not configured");
            return;
        }
        final String alias = provider.get().config().alias();
        if (context.getAttribute(TX_ATTRIBUTE) instanceof String previous) {
            provider.get().transactions().discard(previous); // one live verification per step
        }
        final String state = token();
        final String binding = BrowserBinding.begin(session, context.realmId(), alias);
        final IdentityProvider.RedirectResponse redirect;
        try {
            redirect = provider.get().startVerify(
                    new IdentityProvider.AuthnRequestContext(context.realmId(), state, null, binding), context.userId());
        } catch (final IllegalStateException e) {
            LOG.warn("wallet verify: could not start: realm={} alias={} error={}", LogSafe.sanitize(context.realmId()),
                    LogSafe.sanitize(alias), LogSafe.sanitize(e.getMessage()));
            context.failure("wallet verification could not start");
            return;
        }
        context.putAttribute(STATE_ATTRIBUTE, state);
        final Map<String, String> parameters = redirect.parameters();
        if (parameters != null && parameters.get(WalletIdentityProvider.TRANSACTION_PARAM) != null) {
            context.putAttribute(TX_ATTRIBUTE, parameters.get(WalletIdentityProvider.TRANSACTION_PARAM));
        }
        context.putAttribute(REDIRECT_ATTRIBUTE, redirect.location());
        context.challenge(VIEW);
    }

    @Override
    public void action(final AuthenticationContext context) {
        final String code = context.formParameter(WalletIdentityProvider.RESPONSE_CODE_PARAM);
        if (code == null || code.isBlank()) {
            // "try again" (restart) or an empty submit: ask again; the engine then runs authenticate(), which starts
            // a new verification and sends the browser to the wallet page.
            context.challenge(VIEW);
            return;
        }
        final Optional<WalletIdentityProvider> provider = provider(context);
        final HttpSession session = session();
        if (context.userId() == null || provider.isEmpty() || session == null) {
            context.failure("wallet verification is not configured");
            return;
        }
        final WalletIdentityProvider wallet = provider.get();
        final String alias = wallet.config().alias();
        final String state = context.getAttribute(STATE_ATTRIBUTE) instanceof String s ? s : null;
        final WalletIdentityProvider.VerifyRedemption redeemed;
        try {
            redeemed = wallet.redeemVerify(new IdentityProvider.CallbackContext(context.realmId(),
                    Map.of(WalletIdentityProvider.RESPONSE_CODE_PARAM, code), state, null, null, null,
                    BrowserBinding.current(session, context.realmId(), alias)));
        } catch (final WalletVerificationException e) {
            refuse(context, alias, null, null, e.code());
            return;
        }
        // Redeemed: this browser's verification is over, whatever follows.
        context.putAttribute(STATE_ATTRIBUTE, null);
        context.putAttribute(TX_ATTRIBUTE, null);
        BrowserBinding.clear(session, context.realmId(), alias);
        final VerifiedIdentityJson.Verification v = redeemed.verification();
        if (!context.userId().equals(redeemed.initiatingUserId())) {
            refuse(context, alias, redeemed.transactionId(), v, WalletErrorCode.BINDING_MISMATCH);
            return;
        }
        final Optional<WalletErrorCode> binding = binding(context.realmId(), wallet.config().subject().linkedProvider(),
                v, context.userId());
        if (binding.isPresent()) {
            refuse(context, alias, redeemed.transactionId(), v, binding.get());
            return;
        }
        context.assertLevelOfAssurance(v.levelOfAssurance());
        final Optional<String> pinned = v.claims().isEmpty() ? Optional.empty() : pendingRelease(v);
        final boolean release = pinned.isPresent();
        pinned.ifPresent(context::releaseVerifiedClaims);
        audit.emit(WalletVerifyAudit.success(context.realmId(), context.userId(), redeemed.transactionId(), alias,
                v.format(), v.issuerDn(), release ? v.claims().keySet() : List.of()));
        LOG.info("wallet verify: verified, realm={} alias={} user={} tx={} released={}",
                LogSafe.sanitize(context.realmId()), LogSafe.sanitize(alias), LogSafe.sanitize(context.userId()),
                redeemed.transactionId(), release ? v.claims().keySet() : List.of());
        context.success();
    }

    /**
     * Design D4: empty when the presented wallet is {@code userId}'s at the linked login connection; else why not.
     * The administrative number wins: linked to another user is a mismatch even when the tuple is this user's.
     */
    private Optional<WalletErrorCode> binding(final String realmId, final String linkedAlias,
                                              final VerifiedIdentityJson.Verification v, final String userId) {
        if (linkedAlias == null) {
            return Optional.of(WalletErrorCode.SUBJECT_UNAVAILABLE);
        }
        if (v.numberSubject() != null) {
            final Optional<String> owner = links.find(realmId, linkedAlias,
                    new WalletSubject.AdminNumber(v.numberSubject(), null));
            if (owner.isPresent()) {
                return owner.get().equals(userId) ? Optional.empty() : Optional.of(WalletErrorCode.BINDING_MISMATCH);
            }
        }
        if (v.tupleSubject() != null) {
            final Optional<String> owner = links.find(realmId, linkedAlias, new WalletSubject.Tuple(v.tupleSubject()));
            if (owner.isPresent()) {
                return owner.get().equals(userId) ? Optional.empty() : Optional.of(WalletErrorCode.BINDING_MISMATCH);
            }
        }
        return Optional.of(WalletErrorCode.SUBJECT_UNAVAILABLE); // not linked: link the wallet first
    }

    private void refuse(final AuthenticationContext context, final String alias, final String transactionId,
                        final VerifiedIdentityJson.Verification v, final WalletErrorCode code) {
        audit.emit(WalletVerifyAudit.failure(context.realmId(), context.userId(), transactionId, alias,
                v == null ? null : v.format(), v == null ? null : v.issuerDn(), code));
        LOG.warn("wallet verify: refused, realm={} alias={} user={} reason={}", LogSafe.sanitize(context.realmId()),
                LogSafe.sanitize(alias), LogSafe.sanitize(context.userId()), code.reason());
        context.failure(code.reason());
    }

    /** The configured verify-only connection serving the realm, if any. */
    private Optional<WalletIdentityProvider> provider(final AuthenticationContext context) {
        final String alias = context.config(PROVIDER_ALIAS);
        if (alias == null || alias.isBlank()) {
            LOG.warn("wallet verify: the step has no {} configured (realm={})", PROVIDER_ALIAS,
                    LogSafe.sanitize(context.realmId()));
            return Optional.empty();
        }
        final Optional<WalletIdentityProvider> provider;
        try {
            provider = WalletIdentityProvider.from(registry.get(context.realmId(), alias.trim()))
                    .filter(p -> p.servesRealm(context.realmId()) && p.config().subject().verifyOnly());
        } catch (final IllegalArgumentException absent) {
            LOG.warn("wallet verify: no wallet connection '{}' in realm {}", LogSafe.sanitize(alias),
                    LogSafe.sanitize(context.realmId()));
            return Optional.empty();
        }
        if (provider.isEmpty()) {
            LOG.warn("wallet verify: '{}' is not a verify-only wallet connection of realm {}", LogSafe.sanitize(alias),
                    LogSafe.sanitize(context.realmId()));
        }
        return provider;
    }

    /**
     * The release, pinned to the authorization request this login completes (security review items 1 and 7): only when
     * one is pending and it asks for the {@code verified_claims} scope; bound later to that request's code only
     * ({@link io.helixiam.authorization.security.session.PendingVerifiedClaims}), within its TTL.
     */
    private Optional<String> pendingRelease(final VerifiedIdentityJson.Verification v) {
        final HttpServletRequest request = request();
        if (request == null || InFlightClientResolver.pendingAuthorizeUrl(request).isEmpty()) {
            return Optional.empty();
        }
        final String clientId = InFlightClientResolver.pendingAuthorizeParameter(request, "client_id").orElse(null);
        final String scope = InFlightClientResolver.pendingAuthorizeParameter(request, "scope").orElse("");
        if (clientId == null || !java.util.Arrays.asList(scope.trim().split("\\s+")).contains(
                io.helixiam.authorization.security.session.SsoSessionBindingAuthorizationService.VERIFIED_CLAIMS_SCOPE)) {
            return Optional.empty();
        }
        final String hash = io.helixiam.authorization.security.session.PendingVerifiedClaims.requestHash(clientId,
                InFlightClientResolver.pendingAuthorizeParameter(request, "state").orElse(null),
                InFlightClientResolver.pendingAuthorizeParameter(request, "nonce").orElse(null),
                InFlightClientResolver.pendingAuthorizeParameter(request, "redirect_uri").orElse(null));
        return Optional.of(io.helixiam.authorization.security.session.PendingVerifiedClaims.wrap(verifiedClaimsJson(v),
                clientId, hash, Instant.now(clock).plusSeconds(
                        io.helixiam.authorization.security.session.PendingVerifiedClaims.TTL_SECONDS)));
    }

    /** OIDC for Identity Assurance-style {@code verified_claims} (design D6). */
    private String verifiedClaimsJson(final VerifiedIdentityJson.Verification v) {
        final ObjectNode node = JsonNodeFactory.instance.objectNode();
        final ObjectNode verification = node.putObject("verification");
        verification.put("trust_framework", TRUST_FRAMEWORK);
        verification.put("assurance_level", v.levelOfAssurance());
        verification.put("time", Instant.now(clock).truncatedTo(ChronoUnit.SECONDS).toString());
        final ObjectNode claims = node.putObject("claims");
        v.claims().forEach((name, value) -> {
            if (value instanceof Boolean b) {
                claims.put(name, b);
            } else {
                claims.put(name, String.valueOf(value));
            }
        });
        try {
            return StrictJson.MAPPER.writeValueAsString(node);
        } catch (final JsonProcessingException e) {
            throw new IllegalStateException("Could not encode verified_claims", e);
        }
    }

    private static HttpServletRequest request() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes servlet
                ? servlet.getRequest() : null;
    }

    private static HttpSession session() {
        final HttpServletRequest request = request();
        return request == null ? null : request.getSession(true);
    }

    private String token() {
        final byte[] bytes = new byte[STATE_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
