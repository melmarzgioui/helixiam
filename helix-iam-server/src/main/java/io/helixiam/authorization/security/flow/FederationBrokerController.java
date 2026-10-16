/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.federation.AccountLinkingPolicy;
import io.helixiam.authorization.federation.BrokerResult;
import io.helixiam.authorization.federation.FederatedLoginCompleter;
import io.helixiam.authorization.federation.IdentityBroker;
import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfigPublisher;
import io.helixiam.authorization.amqp.federation.IdentityProviderRef;
import io.helixiam.authorization.federation.saml.Saml2IdentityProvider;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.wallet.VerifiedIdentityJson;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.WalletLinkService;
import io.helixiam.authorization.federation.wallet.WalletLoginCompleter;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Helix IAM E5.3: the federation broker endpoint that drives external (federated) login.
 *
 * <ul>
 *   <li>{@code GET /broker/{alias}} — starts authentication at the external IdP. It mints a fresh
 *       anti-forgery {@code state}, asks the {@link IdentityProvider} to build the redirect
 *       (authorize URL / SAML AuthnRequest), and stashes the {@code state} + the provider's nonce in
 *       the session so the callback can prove the response is genuine (CSRF + replay).</li>
 *   <li>{@code GET|POST /broker/{alias}/callback} — the IdP returns here (OIDC code via GET, SAML
 *       Response via POST). The provider validates the response (signature / state / nonce) and
 *       normalizes it; the {@link IdentityBroker} maps it to a local user (link / JIT); on success
 *       {@link FederatedSessionEstablisher} establishes the login session.</li>
 * </ul>
 *
 * <p>The anti-forgery values are single-use: consumed from the session on callback. A provider
 * validation failure or an unresolved identity is redirected to {@code /login?error} and never
 * establishes a session.
 *
 * <p>Follow-up: a post-broker step-up flow (e.g. force OTP after first federated login) — for now a
 * validated external login establishes the session directly, trusting the IdP's assurance.
 */
@Controller
public class FederationBrokerController {

    private static final Logger LOG = LogManager.getLogger(FederationBrokerController.class);

    private static final String STATE_ATTR = "HELIX_FED_STATE_";
    private static final String NONCE_ATTR = "HELIX_FED_NONCE_";
    /**
     * SAML-1 (S-H1): the outbound AuthnRequest id the SAML broker minted at {@code start}, stashed
     * server-side (in the HTTP session, keyed by alias) so the callback binds the assertion's
     * {@code InResponseTo} to THIS session's request and consumes it single-use. Not derivable from
     * RelayState, so it cannot be forged by an attacker replaying a captured response.
     */
    private static final String REQUEST_ID_ATTR = "HELIX_FED_SAML_REQ_ID_";
    /** SSO P9: the broker alias + subject of the upstream IdP this session was federated through. */
    public static final String IDP_SOURCE_ATTR = "HELIX_IDP_SOURCE";
    public static final String IDP_SUBJECT_ATTR = "HELIX_IDP_SUBJECT";
    private static final String LOGIN_ERROR = "redirect:/login?error=federation";
    /** Task 18 fix round 1: the id of this browser's live wallet login per alias (one at a time). */
    private static final String WALLET_TX_ATTR = "HELIX_WALLET_TX_";

    private final IdentityProviderRegistry registry;
    private final IdentityBroker broker;
    private final AccountLinkingPolicy policy;
    private final FederatedLoginCompleter loginCompleter;
    /** B5: source of the per-IdP attribute/claim mappers; nullable in unit tests (then mappers are skipped). */
    private final IdentityProviderConfigPublisher idpConfig;
    private final String idpBaseUrl;
    private final Supplier<String> stateGenerator;
    /** Task 18: completes EUDI wallet logins (account decision, JIT, link); without it a wallet callback is refused. */
    private WalletLoginCompleter walletLoginCompleter;

    @org.springframework.beans.factory.annotation.Autowired
    public FederationBrokerController(final IdentityProviderRegistry registry, final IdentityBroker broker,
                                      final AccountLinkingPolicy policy,
                                      final FederatedLoginCompleter loginCompleter,
                                      final IdentityProviderConfigPublisher idpConfig,
                                      @Value("${idp.base.url}") final String idpBaseUrl) {
        this(registry, broker, policy, loginCompleter, idpConfig, idpBaseUrl, FederationBrokerController::randomToken);
    }

    // Unit-test constructor (no idp-config source → mappers skipped).
    FederationBrokerController(final IdentityProviderRegistry registry, final IdentityBroker broker,
                               final AccountLinkingPolicy policy,
                               final FederatedLoginCompleter loginCompleter,
                               final String idpBaseUrl, final Supplier<String> stateGenerator) {
        this(registry, broker, policy, loginCompleter, null, idpBaseUrl, stateGenerator);
    }

    FederationBrokerController(final IdentityProviderRegistry registry, final IdentityBroker broker,
                               final AccountLinkingPolicy policy,
                               final FederatedLoginCompleter loginCompleter,
                               final IdentityProviderConfigPublisher idpConfig,
                               final String idpBaseUrl, final Supplier<String> stateGenerator) {
        this.registry = registry;
        this.broker = broker;
        this.policy = policy;
        this.loginCompleter = loginCompleter;
        this.idpConfig = idpConfig;
        this.idpBaseUrl = idpBaseUrl;
        this.stateGenerator = stateGenerator;
    }

    /** Task 18: the wallet-aware completion (setter, so the existing constructors and their callers stay as they are). */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setWalletLoginCompleter(final WalletLoginCompleter walletLoginCompleter) {
        this.walletLoginCompleter = walletLoginCompleter;
    }

    /** Round 6: linking a provider from the account console (absent in slim unit-test wiring). */
    private io.helixiam.authorization.controller.account.console.AccountIdentityLinkFlow linkFlow;
    private static final String ACCOUNT_IDENTITIES = "redirect:/account#identities";

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setLinkFlow(final io.helixiam.authorization.controller.account.console.AccountIdentityLinkFlow linkFlow) {
        this.linkFlow = linkFlow;
    }

    @GetMapping("/broker/{alias}")
    public String start(@PathVariable final String alias, final HttpServletRequest request, final Model model) {
        final IdentityProvider provider;
        try {
            provider = registry.get(RealmContextHolder.get(), alias);
        } catch (final IllegalArgumentException e) {
            // no such provider in this realm (a stored provider of another realm included): the login page's error
            LOG.warn("Federation: no provider {} in this realm", LogSafe.sanitize(alias));
            return LOGIN_ERROR;
        }
        if (!provider.signInCapable()) {
            // A verify-only wallet connection is never a sign-in: refused BEFORE touching this browser's binding for
            // the alias, which a running wallet verification step owns (security review item 4).
            LOG.warn("Federation: provider {} cannot sign anyone in", LogSafe.sanitize(alias));
            return LOGIN_ERROR;
        }
        final String state = stateGenerator.get();
        final HttpSession session = request.getSession();
        final String linkToken = request.getParameter("link");
        if (linkToken != null) {
            // Round 6: an account-console link; only for this session's own, unexpired intent of the signed-in user.
            if (linkFlow == null || WalletIdentityProvider.from(provider).isPresent()
                    || !linkFlow.bindState(session, RealmContextHolder.get(), alias, linkToken, state)) {
                LOG.warn("Federation: refused an account link start at provider {}", LogSafe.sanitize(alias));
                org.springframework.web.servlet.support.RequestContextUtils.getOutputFlashMap(request)
                        .put("identityError", "refused");
                return ACCOUNT_IDENTITIES;
            }
        }
        // Task 18 fix round 1: one live wallet login per browser and provider: starting again discards the previous
        // transaction, so one session can never pile transactions up in the store.
        final WalletIdentityProvider wallet = WalletIdentityProvider.from(provider).orElse(null);
        if (wallet != null && session.getAttribute(key(WALLET_TX_ATTR, alias)) instanceof String previous) {
            wallet.transactions().discard(previous);
            session.removeAttribute(key(WALLET_TX_ATTR, alias));
        }
        // Ties this login to this browser (a session secret, not the session id, which rotates); the EUDI wallet
        // provider stores the hash in its transaction and the callback must present the same one.
        final String browserBindingHash = BrowserBinding.begin(session, RealmContextHolder.get(), alias);
        final IdentityProvider.RedirectResponse redirect;
        try {
            redirect = provider.start(new IdentityProvider.AuthnRequestContext(
                    RealmContextHolder.get(), state, callbackUri(alias), browserBindingHash));
        } catch (final RuntimeException e) {
            // e.g. a stored wallet provider asked to start in another realm: the browser only sees error=federation
            BrowserBinding.clear(session, RealmContextHolder.get(), alias);
            LOG.warn("Federation: provider {} refused to start: {}", LogSafe.sanitize(alias),
                    LogSafe.sanitize(e.getMessage()));
            return LOGIN_ERROR;
        }

        session.setAttribute(key(STATE_ATTR, alias), state);
        if (wallet != null && redirect.parameters() != null
                && redirect.parameters().get(WalletIdentityProvider.TRANSACTION_PARAM) != null) {
            session.setAttribute(key(WALLET_TX_ATTR, alias), redirect.parameters().get(WalletIdentityProvider.TRANSACTION_PARAM));
        }
        if (redirect.parameters() != null && redirect.parameters().get("nonce") != null) {
            session.setAttribute(key(NONCE_ATTR, alias), redirect.parameters().get("nonce"));
        }
        // SAML-1 (S-H1): persist the SAML AuthnRequest id server-side so the callback can require the
        // assertion's InResponseTo to match this session's request (single-use, replay-proof).
        if (redirect.parameters() != null
                && redirect.parameters().get(Saml2IdentityProvider.REQUEST_ID_PARAM) != null) {
            session.setAttribute(key(REQUEST_ID_ATTR, alias), redirect.parameters().get(Saml2IdentityProvider.REQUEST_ID_PARAM));
        }
        LOG.info("Federation: starting login at provider {} ({})",
                LogSafe.sanitize(alias), LogSafe.sanitize(redirect.binding()));

        if (redirect.binding() == IdentityProvider.Binding.POST) {
            // SAML HTTP-POST binding (DigiD/eHerkenning): render an auto-submitting form to the IdP.
            model.addAttribute("action", redirect.location());
            model.addAttribute("fields", redirect.formFields());
            return "flow/saml-post";
        }
        return "redirect:" + redirect.location();
    }

    @GetMapping("/broker/{alias}/callback")
    public String callback(@PathVariable final String alias, final HttpServletRequest request,
                           final HttpServletResponse response) {
        return handleCallback(alias, request, response);
    }

    @PostMapping("/broker/{alias}/callback")
    public String callbackPost(@PathVariable final String alias, final HttpServletRequest request,
                               final HttpServletResponse response) {
        return handleCallback(alias, request, response);
    }

    private String handleCallback(final String alias, final HttpServletRequest request,
                                  final HttpServletResponse response) {
        final HttpSession session = request.getSession();
        final String expectedState = (String) session.getAttribute(key(STATE_ATTR, alias));
        final String expectedNonce = (String) session.getAttribute(key(NONCE_ATTR, alias));
        final String expectedRequestId = (String) session.getAttribute(key(REQUEST_ID_ATTR, alias));
        // Single-use: consume the anti-forgery values + the pending SAML request id regardless of outcome
        // (a replayed response then finds no pending request id → InResponseTo binding rejects it).
        session.removeAttribute(key(STATE_ATTR, alias));
        session.removeAttribute(key(NONCE_ATTR, alias));
        session.removeAttribute(key(REQUEST_ID_ATTR, alias));

        final BrokeredIdentity identity;
        VerifiedIdentityJson.StoredLogin walletLogin = null;
        try {
            final IdentityProvider provider = registry.get(RealmContextHolder.get(), alias);
            final IdentityProvider.CallbackContext context = new IdentityProvider.CallbackContext(
                    RealmContextHolder.get(), parameters(request), expectedState, expectedNonce,
                    callbackUri(alias), expectedRequestId,
                    BrowserBinding.current(session, RealmContextHolder.get(), alias));
            final WalletIdentityProvider walletProvider = WalletIdentityProvider.from(provider).orElse(null);
            if (walletProvider != null) {
                // Task 18: a wallet login carries the account decision made when the presentation was verified; it
                // never goes through IdentityBroker (no email linking, no overwriting link).
                if (walletLoginCompleter == null) {
                    throw new IllegalStateException("EUDI wallet logins are not wired");
                }
                walletLogin = walletProvider.redeem(context);
                identity = walletLogin.identity();
            } else {
                identity = provider.callback(context);
            }
        } catch (final WalletVerificationException e) {
            // The browser only ever sees error=federation; which check failed is logged, never shown.
            LOG.warn("Federation: wallet callback refused for provider {}: reason={} detail={}",
                    LogSafe.sanitize(alias), e.code().reason(), LogSafe.sanitize(e.getMessage()));
            return LOGIN_ERROR;
        } catch (final RuntimeException e) {
            LOG.warn("Federation: callback validation failed for provider {}: {}",
                    LogSafe.sanitize(alias), LogSafe.sanitize(e.getMessage()));
            return LOGIN_ERROR;
        }
        BrowserBinding.clear(session, RealmContextHolder.get(), alias);

        if (walletLogin != null) {
            session.removeAttribute(key(WALLET_TX_ATTR, alias)); // redeemed: nothing left to discard
            if (!(walletLogin.decision() instanceof WalletLinkService.Decision.Refused)) {
                session.setAttribute(IDP_SOURCE_ATTR, alias);
                session.setAttribute(IDP_SUBJECT_ATTR, identity.externalSubject());
            }
            try {
                return walletLoginCompleter.complete(alias, walletLogin, mapperConfigFor(alias), request, response);
            } catch (final RuntimeException e) {
                // Task 18 fix round 1: e.g. the link store or provisioning failed after a verified login; the browser
                // only ever sees error=federation (no detail, no PII in the log: the exception type only).
                LOG.warn("Federation: wallet login for provider {} could not be completed: {}",
                        LogSafe.sanitize(alias), e.getClass().getSimpleName());
                return LOGIN_ERROR;
            }
        }

        // Round 6: the callback of an account-console link links the identity to the signed-in user; never a sign-in.
        if (linkFlow != null) {
            final java.util.Optional<io.helixiam.authorization.controller.account.console.AccountIdentityLinkFlow.Intent>
                    intent = linkFlow.take(session, alias, expectedState);
            if (intent.isPresent()) {
                final var outcome = linkFlow.complete(intent.get(), identity, request);
                final boolean ok = outcome == io.helixiam.authorization.controller.account.console
                        .AccountIdentityLinkFlow.Outcome.LINKED || outcome == io.helixiam.authorization.controller
                        .account.console.AccountIdentityLinkFlow.Outcome.ALREADY_LINKED;
                final var flash = org.springframework.web.servlet.support.RequestContextUtils.getOutputFlashMap(request);
                flash.put(ok ? "identityStatus" : "identityError",
                        outcome.name().toLowerCase(java.util.Locale.ROOT).replace('_', '-'));
                flash.put("identityAlias", alias);
                return ACCOUNT_IDENTITIES;
            }
        }

        // B5: apply this provider's configured attribute/claim mappers during link/JIT provisioning.
        final BrokerResult result = broker.broker(identity, policy, mapperConfigFor(alias));
        if (!result.resolved()) {
            LOG.warn("Federation: identity {}:{} from provider {} was not resolved to a local user",
                    LogSafe.sanitize(alias), LogSafe.sanitize(identity.externalSubject()), LogSafe.sanitize(alias));
            return LOGIN_ERROR;
        }

        LOG.info("Federation: provider {} resolved user {} (provisioned={}, linked={}) — completing login",
                LogSafe.sanitize(alias), LogSafe.sanitize(result.userId()), result.provisioned(), result.linked());
        // SSO P9: remember which upstream IdP this session was brokered through, plus the subject, so a later
        // logout can propagate a Single Logout to that IdP (FederatedLogoutCoordinator).
        session.setAttribute(IDP_SOURCE_ATTR, alias);
        session.setAttribute(IDP_SUBJECT_ATTR, identity.externalSubject());
        // Run the post-broker flow (optional step-up); it establishes the session or routes to /flow.
        // Task 3 (fix round 1): ONLY the typed BrokeredIdentity#levelOfAssurance() may reach acr — NEVER
        // identity.attributes().get("loa"), which is free-form/provider-controlled and forgeable (any OIDC
        // IdP whose id_token carries a "loa" claim would otherwise set it verbatim).
        return loginCompleter.complete(result.userId(), identity.levelOfAssurance(), request, response);
    }

    /**
     * B5: fetch the provider's configured {@code mappers} CSV for the current realm (or null when no
     * config source is wired / none configured / lookup fails — federation still proceeds with defaults).
     */
    private String mapperConfigFor(final String alias) {
        if (idpConfig == null) {
            return null;
        }
        try {
            final IdentityProviderConfig config = idpConfig.get(new IdentityProviderRef(RealmContextHolder.get(), alias));
            return config == null || config.config() == null ? null : config.config().get("mappers");
        } catch (final RuntimeException e) {
            LOG.debug("Federation: mapper config lookup failed for provider {}: {}",
                    LogSafe.sanitize(alias), LogSafe.sanitize(e.getMessage()));
            return null;
        }
    }

    /**
     * The session attribute of a per-login value of {@code alias} in the request's realm (production readiness item 2):
     * keyed by (realm, alias), so two realms using one alias in one browser do not clobber each other.
     */
    private static String key(final String prefix, final String alias) {
        return BrowserBinding.sessionKey(prefix, RealmContextHolder.get(), alias);
    }

    /** Realm-prefixed external callback the IdP redirects back to: {@code {idpBase}/realms/{realm}/broker/{alias}/callback}. */
    private String callbackUri(final String alias) {
        return idpBaseUrl + "/realms/" + RealmContextHolder.get() + "/broker/" + alias + "/callback";
    }

    private static Map<String, String> parameters(final HttpServletRequest request) {
        final Map<String, String> params = new HashMap<>();
        request.getParameterMap().forEach((key, values) -> {
            if (values != null && values.length > 0) {
                params.put(key, values[0]);
            }
        });
        return params;
    }

    private static String randomToken() {
        final byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
