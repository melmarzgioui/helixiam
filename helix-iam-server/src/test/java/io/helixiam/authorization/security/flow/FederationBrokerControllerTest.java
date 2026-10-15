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
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E5.3: the federation broker endpoint. {@code GET /broker/{alias}} starts authentication
 * at the external IdP (stashing the anti-forgery state + nonce in the session); the callback verifies
 * the IdP's response via the provider, brokers it to a local user, and on success establishes the
 * login session. Proves the anti-forgery values round-trip, a resolved user logs in, and an
 * unresolved/failed callback is rejected without establishing a session.
 */
class FederationBrokerControllerTest {

    private static final String SP = "https://helix.test";
    private static final String ALIAS = "corp";

    private final IdentityProviderRegistry registry = mock(IdentityProviderRegistry.class);
    private final IdentityBroker broker = mock(IdentityBroker.class);
    private final FederatedLoginCompleter loginCompleter = mock(FederatedLoginCompleter.class);
    private final IdentityProvider provider = mock(IdentityProvider.class);

    private final FederationBrokerController controller = new FederationBrokerController(
            registry, broker, AccountLinkingPolicy.defaults(), loginCompleter, SP, () -> "fixed-state");

    // Helix IAM multi-tenant (MT-3/MT-4): the broker runs inside a /realms/{realm}/… request, so the
    // realm context is bound; outbound callbacks must carry that realm.
    @BeforeEach
    void bindRealm() {
        RealmContextHolder.set("gov");
        // a mock answers false for the SPI's default signInCapable(); these providers sign users in
        org.mockito.Mockito.when(provider.signInCapable()).thenReturn(true);
    }

    @Test
    void aProviderThatCannotSignIn_isRefused_beforeTheBrowserBindingIsTouched() {
        org.mockito.Mockito.when(provider.signInCapable()).thenReturn(false);
        org.mockito.Mockito.when(registry.get("gov", "verify")).thenReturn(provider);
        final org.springframework.mock.web.MockHttpServletRequest request =
                new org.springframework.mock.web.MockHttpServletRequest();
        final String binding = BrowserBinding.begin(request.getSession(true), "gov", "verify");
        final String view = controller.start("verify", request, new org.springframework.ui.ExtendedModelMap());
        org.assertj.core.api.Assertions.assertThat(view).contains("/login?error=federation");
        org.assertj.core.api.Assertions.assertThat(BrowserBinding.current(request.getSession(false), "gov", "verify"))
                .as("the step's binding is untouched").isEqualTo(binding);
        org.mockito.Mockito.verify(provider, org.mockito.Mockito.never()).start(org.mockito.ArgumentMatchers.any());
    }

    @AfterEach
    void clearRealm() {
        RealmContextHolder.clear();
    }

    @Test
    void startStashesStateAndNonceThenRedirectsToTheIdp() {
        when(registry.get(any(), eq(ALIAS))).thenReturn(provider);
        when(provider.start(any())).thenReturn(
                new IdentityProvider.RedirectResponse("https://idp/authorize?x=1", Map.of("nonce", "n-123")));
        final MockHttpServletRequest request = new MockHttpServletRequest();

        final String view = controller.start(ALIAS, request, new org.springframework.ui.ConcurrentModel());

        assertThat(view).isEqualTo("redirect:https://idp/authorize?x=1");
        // The provider was asked to start with our anti-forgery state + the well-formed callback URI.
        final ArgumentCaptor<IdentityProvider.AuthnRequestContext> ctx =
                ArgumentCaptor.forClass(IdentityProvider.AuthnRequestContext.class);
        verify(provider).start(ctx.capture());
        assertThat(ctx.getValue().state()).isEqualTo("fixed-state");
        assertThat(ctx.getValue().callbackUri()).isEqualTo(SP + "/realms/gov/broker/" + ALIAS + "/callback");
        assertThat(ctx.getValue().realmId()).isEqualTo("gov");
        // State + nonce are stashed in the session for the callback to replay.
        assertThat(request.getSession().getAttribute(BrowserBinding.sessionKey("HELIX_FED_STATE_", "gov", ALIAS))).isEqualTo("fixed-state");
        assertThat(request.getSession().getAttribute(BrowserBinding.sessionKey("HELIX_FED_NONCE_", "gov", ALIAS))).isEqualTo("n-123");
    }

    @Test
    void startRendersAnAutoSubmitPostFormForPostBindingProviders() {
        when(registry.get(any(), eq(ALIAS))).thenReturn(provider);
        when(provider.start(any())).thenReturn(IdentityProvider.RedirectResponse.postForm(
                "https://digid/sso", Map.of("SAMLRequest", "deflated", "RelayState", "fixed-state")));
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final org.springframework.ui.ConcurrentModel model = new org.springframework.ui.ConcurrentModel();

        final String view = controller.start(ALIAS, request, model);

        assertThat(view).isEqualTo("flow/saml-post"); // auto-submit form, not a 302
        assertThat(model.getAttribute("action")).isEqualTo("https://digid/sso");
        assertThat(model.getAttribute("fields")).isEqualTo(Map.of("SAMLRequest", "deflated", "RelayState", "fixed-state"));
        assertThat(request.getSession().getAttribute(BrowserBinding.sessionKey("HELIX_FED_STATE_", "gov", ALIAS))).isEqualTo("fixed-state");
    }

    @Test
    void callbackBrokersAResolvedUserAndCompletesLogin() {
        when(registry.get(any(), eq(ALIAS))).thenReturn(provider);
        final BrokeredIdentity identity = new BrokeredIdentity(ALIAS, "ext-1", "ada@corp", true, Map.of());
        when(provider.callback(any())).thenReturn(identity);
        when(broker.broker(any(), any(), any())).thenReturn(BrokerResult.existingLink("user-9"));

        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(BrowserBinding.sessionKey("HELIX_FED_STATE_", "gov", ALIAS), "fixed-state");
        request.getSession().setAttribute(BrowserBinding.sessionKey("HELIX_FED_NONCE_", "gov", ALIAS), "n-123");
        request.setParameter("state", "fixed-state");
        request.setParameter("code", "auth-code");
        final MockHttpServletResponse response = new MockHttpServletResponse();
        when(loginCompleter.complete("user-9", null, request, response)).thenReturn("redirect:" + SP);

        final String view = controller.callback(ALIAS, request, response);

        assertThat(view).isEqualTo("redirect:" + SP);
        // No "loa" attribute on this identity (not a brokered-LoA provider): the completer is called with none.
        verify(loginCompleter).complete("user-9", null, request, response);
        // The provider got the replayed anti-forgery values + the matching redirect URI.
        final ArgumentCaptor<IdentityProvider.CallbackContext> ctx =
                ArgumentCaptor.forClass(IdentityProvider.CallbackContext.class);
        verify(provider).callback(ctx.capture());
        assertThat(ctx.getValue().expectedState()).isEqualTo("fixed-state");
        assertThat(ctx.getValue().expectedNonce()).isEqualTo("n-123");
        assertThat(ctx.getValue().redirectUri()).isEqualTo(SP + "/realms/gov/broker/" + ALIAS + "/callback");
        assertThat(ctx.getValue().realmId()).isEqualTo("gov");
        assertThat(ctx.getValue().parameters()).containsEntry("code", "auth-code");
        // Anti-forgery values are consumed (single-use).
        assertThat(request.getSession().getAttribute(BrowserBinding.sessionKey("HELIX_FED_STATE_", "gov", ALIAS))).isNull();
    }

    /**
     * Task 3: when the upstream provider asserted a TYPED level of assurance ({@code
     * BrokeredIdentity#levelOfAssurance()} — only a connector that validated it against its own ladder,
     * e.g. the eID SAML connector, may set this), the controller passes it to the completer so it can
     * reach the ID token {@code acr}.
     */
    @Test
    void callbackPassesTheBrokeredLoaToTheLoginCompleter() {
        when(registry.get(any(), eq(ALIAS))).thenReturn(provider);
        final BrokeredIdentity identity = new BrokeredIdentity(ALIAS, "ext-1", "ada@corp", true,
                Map.of(), "http://eidas.europa.eu/LoA/substantial");
        when(provider.callback(any())).thenReturn(identity);
        when(broker.broker(any(), any(), any())).thenReturn(BrokerResult.existingLink("user-9"));

        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(BrowserBinding.sessionKey("HELIX_FED_STATE_", "gov", ALIAS), "fixed-state");
        request.setParameter("state", "fixed-state");
        final MockHttpServletResponse response = new MockHttpServletResponse();
        when(loginCompleter.complete("user-9", "http://eidas.europa.eu/LoA/substantial", request, response))
                .thenReturn("redirect:" + SP);

        final String view = controller.callback(ALIAS, request, response);

        assertThat(view).isEqualTo("redirect:" + SP);
        verify(loginCompleter).complete("user-9", "http://eidas.europa.eu/LoA/substantial", request, response);
    }

    /**
     * [Critical fix round 1] Forged acr: a provider's free-form {@code attributes} map is NEVER the source
     * of acr — only the typed {@code levelOfAssurance()}. Without this, any OIDC IdP whose id_token (or any
     * provider whose generic attributes) happens to carry a key named {@code "loa"} could set Helix's acr
     * verbatim (e.g. forging {@code http://eidas.europa.eu/LoA/high}).
     */
    @Test
    void callbackNeverTrustsAForgedAttributesLoaKey_onlyTheTypedLevelOfAssurance() {
        when(registry.get(any(), eq(ALIAS))).thenReturn(provider);
        // Forged: a generic attribute happens to be named "loa", but this identity asserts NO typed LoA
        // (the 5-arg compatibility constructor — what every non-eID provider, e.g. OIDC, actually uses).
        final BrokeredIdentity identity = new BrokeredIdentity(ALIAS, "ext-1", "ada@corp", true,
                Map.of("loa", "http://eidas.europa.eu/LoA/high"));
        when(provider.callback(any())).thenReturn(identity);
        when(broker.broker(any(), any(), any())).thenReturn(BrokerResult.existingLink("user-9"));

        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(BrowserBinding.sessionKey("HELIX_FED_STATE_", "gov", ALIAS), "fixed-state");
        request.setParameter("state", "fixed-state");
        final MockHttpServletResponse response = new MockHttpServletResponse();
        when(loginCompleter.complete("user-9", null, request, response)).thenReturn("redirect:" + SP);

        final String view = controller.callback(ALIAS, request, response);

        assertThat(view).isEqualTo("redirect:" + SP);
        verify(loginCompleter).complete("user-9", null, request, response);
    }

    @Test
    void startPersistsTheSamlRequestIdAndCallbackBindsThenConsumesItSingleUse() {
        // SAML-1 (S-H1): the broker persists the minted AuthnRequest id server-side (session), passes it
        // to the callback as expectedRequestId, and consumes it single-use so a replay finds none.
        when(registry.get(any(), eq(ALIAS))).thenReturn(provider);
        when(provider.start(any())).thenReturn(new IdentityProvider.RedirectResponse(
                "https://idp/sso?x=1", Map.of("samlRequestId", "_req-1")));
        final BrokeredIdentity identity = new BrokeredIdentity(ALIAS, "ext-1", "ada@corp", true, Map.of());
        when(provider.callback(any())).thenReturn(identity);
        when(broker.broker(any(), any(), any())).thenReturn(BrokerResult.existingLink("user-9"));

        final MockHttpServletRequest request = new MockHttpServletRequest();
        controller.start(ALIAS, request, new org.springframework.ui.ConcurrentModel());
        // Persisted server-side, keyed by alias.
        assertThat(request.getSession().getAttribute(BrowserBinding.sessionKey("HELIX_FED_SAML_REQ_ID_", "gov", ALIAS))).isEqualTo("_req-1");

        final MockHttpServletResponse response = new MockHttpServletResponse();
        when(loginCompleter.complete("user-9", null, request, response)).thenReturn("redirect:" + SP);
        controller.callback(ALIAS, request, response);

        // The pending request id was handed to the provider for the InResponseTo binding...
        final ArgumentCaptor<IdentityProvider.CallbackContext> ctx =
                ArgumentCaptor.forClass(IdentityProvider.CallbackContext.class);
        verify(provider).callback(ctx.capture());
        assertThat(ctx.getValue().expectedRequestId()).isEqualTo("_req-1");
        // ...and consumed (single-use): a replayed callback now presents no pending request id.
        assertThat(request.getSession().getAttribute(BrowserBinding.sessionKey("HELIX_FED_SAML_REQ_ID_", "gov", ALIAS))).isNull();
    }

    @Test
    void callbackRejectsAnUnresolvedIdentityWithoutEstablishingASession() {
        when(registry.get(any(), eq(ALIAS))).thenReturn(provider);
        when(provider.callback(any())).thenReturn(new BrokeredIdentity(ALIAS, "ext-1", null, false, Map.of()));
        when(broker.broker(any(), any(), any())).thenReturn(BrokerResult.unresolved());

        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(BrowserBinding.sessionKey("HELIX_FED_STATE_", "gov", ALIAS), "fixed-state");
        request.setParameter("state", "fixed-state");
        final MockHttpServletResponse response = new MockHttpServletResponse();

        final String view = controller.callback(ALIAS, request, response);

        assertThat(view).startsWith("redirect:/login?error");
        verify(loginCompleter, never()).complete(any(), any(), any());
        verify(loginCompleter, never()).complete(any(), any(), any(), any());
    }

    @Test
    void callbackRejectsAFailedProviderValidationWithoutEstablishingASession() {
        when(registry.get(any(), eq(ALIAS))).thenReturn(provider);
        when(provider.callback(any())).thenThrow(new IllegalStateException("state mismatch (possible CSRF)"));

        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(BrowserBinding.sessionKey("HELIX_FED_STATE_", "gov", ALIAS), "fixed-state");
        request.setParameter("state", "attacker");
        final MockHttpServletResponse response = new MockHttpServletResponse();

        final String view = controller.callback(ALIAS, request, response);

        assertThat(view).startsWith("redirect:/login?error");
        verify(loginCompleter, never()).complete(any(), any(), any());
        verify(loginCompleter, never()).complete(any(), any(), any(), any());
        verify(broker, never()).broker(any(), any());
    }

    // ------------------------------------------------------------------ browser binding (EUDI wallet, ruling 1)

    @Test
    void startBindsTheLoginToThisBrowserAndPassesTheHashToTheProvider() {
        when(registry.get(any(), eq(ALIAS))).thenReturn(provider);
        when(provider.start(any())).thenReturn(new IdentityProvider.RedirectResponse("/realms/gov/broker/corp/wallet?tx=t",
                Map.of()));
        final MockHttpServletRequest request = new MockHttpServletRequest();

        controller.start(ALIAS, request, new org.springframework.ui.ConcurrentModel());

        final ArgumentCaptor<IdentityProvider.AuthnRequestContext> ctx =
                ArgumentCaptor.forClass(IdentityProvider.AuthnRequestContext.class);
        verify(provider).start(ctx.capture());
        assertThat(ctx.getValue().browserBindingHash()).isNotBlank()
                .isEqualTo(BrowserBinding.current(request.getSession(), "gov", ALIAS))
                .isNotEqualTo(request.getSession().getId());
    }

    @Test
    void callbackRecomputesTheBindingAfterSessionIdRotationAndClearsItOnSuccess() {
        when(registry.get(any(), eq(ALIAS))).thenReturn(provider);
        when(provider.start(any())).thenReturn(new IdentityProvider.RedirectResponse("/wallet", Map.of()));
        when(provider.callback(any())).thenReturn(new BrokeredIdentity(ALIAS, "ext-1", null, false, Map.of()));
        when(broker.broker(any(), any(), any())).thenReturn(BrokerResult.existingLink("user-9"));
        final MockHttpServletRequest request = new MockHttpServletRequest();
        controller.start(ALIAS, request, new org.springframework.ui.ConcurrentModel());
        final String bound = BrowserBinding.current(request.getSession(), "gov", ALIAS);
        request.changeSessionId(); // Task 2 rotates ids; the binding must not depend on them
        final MockHttpServletResponse response = new MockHttpServletResponse();

        controller.callback(ALIAS, request, response);

        final ArgumentCaptor<IdentityProvider.CallbackContext> ctx =
                ArgumentCaptor.forClass(IdentityProvider.CallbackContext.class);
        verify(provider).callback(ctx.capture());
        assertThat(ctx.getValue().browserBindingHash()).isEqualTo(bound);
        assertThat(BrowserBinding.current(request.getSession(), "gov", ALIAS)).as("cleared after success").isNull();
    }

    @Test
    void aFailedCallbackKeepsTheBinding() {
        when(registry.get(any(), eq(ALIAS))).thenReturn(provider);
        when(provider.callback(any())).thenThrow(new IllegalStateException("refused"));
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final String bound = BrowserBinding.begin(request.getSession(), "gov", ALIAS);

        final String view = controller.callback(ALIAS, request, new MockHttpServletResponse());

        assertThat(view).isEqualTo("redirect:/login?error=federation");
        assertThat(BrowserBinding.current(request.getSession(), "gov", ALIAS)).isEqualTo(bound);
    }

    // ------------------------------------------------------------------ fix round 1

    @Test
    void aWalletRefusalRedirectsToTheGenericFederationErrorAndLeaksNoReason() {
        when(registry.get(any(), eq(ALIAS))).thenReturn(provider);
        when(provider.callback(any())).thenThrow(new io.helixiam.authorization.federation.wallet
                .WalletVerificationException(io.helixiam.authorization.federation.wallet.WalletErrorCode.REPLAY,
                "response code unknown, expired, already used"));
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();

        final String view = controller.callback(ALIAS, request, response);

        assertThat(view).isEqualTo("redirect:/login?error=federation");
        assertThat(view.toLowerCase()).doesNotContain("replay").doesNotContain("wallet").doesNotContain("code");
        assertThat(response.getContentAsByteArray()).isEmpty();
        assertThat(response.getHeaderNames()).isEmpty();
        verify(broker, never()).broker(any(), any(), any());
    }

    @Test
    void aProviderThatRefusesToStartGoesToTheFederationErrorPage() {
        when(registry.get(any(), eq(ALIAS))).thenReturn(provider);
        when(provider.start(any())).thenThrow(new IllegalStateException("provider not usable in this realm"));
        final MockHttpServletRequest request = new MockHttpServletRequest();

        final String view = controller.start(ALIAS, request, new org.springframework.ui.ConcurrentModel());

        assertThat(view).isEqualTo("redirect:/login?error=federation");
        assertThat(request.getSession().getAttribute(BrowserBinding.sessionKey("HELIX_FED_STATE_", "gov", ALIAS))).isNull();
    }
}
