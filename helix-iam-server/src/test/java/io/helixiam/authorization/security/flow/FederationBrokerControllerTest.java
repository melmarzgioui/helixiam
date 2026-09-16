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
    }

    @AfterEach
    void clearRealm() {
        RealmContextHolder.clear();
    }

    @Test
    void startStashesStateAndNonceThenRedirectsToTheIdp() {
        when(registry.get(ALIAS)).thenReturn(provider);
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
        assertThat(request.getSession().getAttribute("HELIX_FED_STATE_" + ALIAS)).isEqualTo("fixed-state");
        assertThat(request.getSession().getAttribute("HELIX_FED_NONCE_" + ALIAS)).isEqualTo("n-123");
    }

    @Test
    void startRendersAnAutoSubmitPostFormForPostBindingProviders() {
        when(registry.get(ALIAS)).thenReturn(provider);
        when(provider.start(any())).thenReturn(IdentityProvider.RedirectResponse.postForm(
                "https://digid/sso", Map.of("SAMLRequest", "deflated", "RelayState", "fixed-state")));
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final org.springframework.ui.ConcurrentModel model = new org.springframework.ui.ConcurrentModel();

        final String view = controller.start(ALIAS, request, model);

        assertThat(view).isEqualTo("flow/saml-post"); // auto-submit form, not a 302
        assertThat(model.getAttribute("action")).isEqualTo("https://digid/sso");
        assertThat(model.getAttribute("fields")).isEqualTo(Map.of("SAMLRequest", "deflated", "RelayState", "fixed-state"));
        assertThat(request.getSession().getAttribute("HELIX_FED_STATE_" + ALIAS)).isEqualTo("fixed-state");
    }

    @Test
    void callbackBrokersAResolvedUserAndCompletesLogin() {
        when(registry.get(ALIAS)).thenReturn(provider);
        final BrokeredIdentity identity = new BrokeredIdentity(ALIAS, "ext-1", "ada@corp", true, Map.of());
        when(provider.callback(any())).thenReturn(identity);
        when(broker.broker(any(), any(), any())).thenReturn(BrokerResult.existingLink("user-9"));

        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute("HELIX_FED_STATE_" + ALIAS, "fixed-state");
        request.getSession().setAttribute("HELIX_FED_NONCE_" + ALIAS, "n-123");
        request.setParameter("state", "fixed-state");
        request.setParameter("code", "auth-code");
        final MockHttpServletResponse response = new MockHttpServletResponse();
        when(loginCompleter.complete("user-9", request, response)).thenReturn("redirect:" + SP);

        final String view = controller.callback(ALIAS, request, response);

        assertThat(view).isEqualTo("redirect:" + SP);
        verify(loginCompleter).complete("user-9", request, response);
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
        assertThat(request.getSession().getAttribute("HELIX_FED_STATE_" + ALIAS)).isNull();
    }

    @Test
    void callbackRejectsAnUnresolvedIdentityWithoutEstablishingASession() {
        when(registry.get(ALIAS)).thenReturn(provider);
        when(provider.callback(any())).thenReturn(new BrokeredIdentity(ALIAS, "ext-1", null, false, Map.of()));
        when(broker.broker(any(), any(), any())).thenReturn(BrokerResult.unresolved());

        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute("HELIX_FED_STATE_" + ALIAS, "fixed-state");
        request.setParameter("state", "fixed-state");
        final MockHttpServletResponse response = new MockHttpServletResponse();

        final String view = controller.callback(ALIAS, request, response);

        assertThat(view).startsWith("redirect:/login?error");
        verify(loginCompleter, never()).complete(any(), any(), any());
    }

    @Test
    void callbackRejectsAFailedProviderValidationWithoutEstablishingASession() {
        when(registry.get(ALIAS)).thenReturn(provider);
        when(provider.callback(any())).thenThrow(new IllegalStateException("state mismatch (possible CSRF)"));

        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute("HELIX_FED_STATE_" + ALIAS, "fixed-state");
        request.setParameter("state", "attacker");
        final MockHttpServletResponse response = new MockHttpServletResponse();

        final String view = controller.callback(ALIAS, request, response);

        assertThat(view).startsWith("redirect:/login?error");
        verify(loginCompleter, never()).complete(any(), any(), any());
        verify(broker, never()).broker(any(), any());
    }
}
