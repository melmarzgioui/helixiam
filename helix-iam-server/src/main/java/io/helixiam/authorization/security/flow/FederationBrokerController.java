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
import io.helixiam.authorization.security.realm.RealmContextHolder;
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

    private final IdentityProviderRegistry registry;
    private final IdentityBroker broker;
    private final AccountLinkingPolicy policy;
    private final FederatedLoginCompleter loginCompleter;
    /** B5: source of the per-IdP attribute/claim mappers; nullable in unit tests (then mappers are skipped). */
    private final IdentityProviderConfigPublisher idpConfig;
    private final String idpBaseUrl;
    private final Supplier<String> stateGenerator;

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

    @GetMapping("/broker/{alias}")
    public String start(@PathVariable final String alias, final HttpServletRequest request, final Model model) {
        final IdentityProvider provider = registry.get(alias);
        final String state = stateGenerator.get();
        final IdentityProvider.RedirectResponse redirect =
                provider.start(new IdentityProvider.AuthnRequestContext(RealmContextHolder.get(), state, callbackUri(alias)));

        final HttpSession session = request.getSession();
        session.setAttribute(STATE_ATTR + alias, state);
        if (redirect.parameters() != null && redirect.parameters().get("nonce") != null) {
            session.setAttribute(NONCE_ATTR + alias, redirect.parameters().get("nonce"));
        }
        // SAML-1 (S-H1): persist the SAML AuthnRequest id server-side so the callback can require the
        // assertion's InResponseTo to match this session's request (single-use, replay-proof).
        if (redirect.parameters() != null
                && redirect.parameters().get(Saml2IdentityProvider.REQUEST_ID_PARAM) != null) {
            session.setAttribute(REQUEST_ID_ATTR + alias, redirect.parameters().get(Saml2IdentityProvider.REQUEST_ID_PARAM));
        }
        LOG.info("Federation: starting login at provider {} ({})", alias, redirect.binding());

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
        final String expectedState = (String) session.getAttribute(STATE_ATTR + alias);
        final String expectedNonce = (String) session.getAttribute(NONCE_ATTR + alias);
        final String expectedRequestId = (String) session.getAttribute(REQUEST_ID_ATTR + alias);
        // Single-use: consume the anti-forgery values + the pending SAML request id regardless of outcome
        // (a replayed response then finds no pending request id → InResponseTo binding rejects it).
        session.removeAttribute(STATE_ATTR + alias);
        session.removeAttribute(NONCE_ATTR + alias);
        session.removeAttribute(REQUEST_ID_ATTR + alias);

        final BrokeredIdentity identity;
        try {
            final IdentityProvider provider = registry.get(alias);
            final IdentityProvider.CallbackContext context = new IdentityProvider.CallbackContext(
                    RealmContextHolder.get(), parameters(request), expectedState, expectedNonce,
                    callbackUri(alias), expectedRequestId);
            identity = provider.callback(context);
        } catch (final RuntimeException e) {
            LOG.warn("Federation: callback validation failed for provider {}: {}", alias, e.getMessage());
            return LOGIN_ERROR;
        }

        // B5: apply this provider's configured attribute/claim mappers during link/JIT provisioning.
        final BrokerResult result = broker.broker(identity, policy, mapperConfigFor(alias));
        if (!result.resolved()) {
            LOG.warn("Federation: identity {}:{} from provider {} was not resolved to a local user",
                    alias, identity.externalSubject(), alias);
            return LOGIN_ERROR;
        }

        LOG.info("Federation: provider {} resolved user {} (provisioned={}, linked={}) — completing login",
                alias, result.userId(), result.provisioned(), result.linked());
        // SSO P9: remember which upstream IdP this session was brokered through, plus the subject, so a later
        // logout can propagate a Single Logout to that IdP (FederatedLogoutCoordinator).
        session.setAttribute(IDP_SOURCE_ATTR, alias);
        session.setAttribute(IDP_SUBJECT_ATTR, identity.externalSubject());
        // Run the post-broker flow (optional step-up); it establishes the session or routes to /flow.
        return loginCompleter.complete(result.userId(), request, response);
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
            LOG.debug("Federation: mapper config lookup failed for provider {}: {}", alias, e.getMessage());
            return null;
        }
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
