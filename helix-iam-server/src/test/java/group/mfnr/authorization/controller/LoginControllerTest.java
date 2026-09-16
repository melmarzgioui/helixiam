package group.mfnr.authorization.controller;

import group.mfnr.authorization.amqp.AuthFlowPublisher;
import group.mfnr.authorization.federation.IdentityProviderRegistry;
import group.mfnr.authorization.federation.spi.BrokeredIdentity;
import group.mfnr.authorization.federation.spi.IdentityProvider;
import group.mfnr.authorization.federation.spi.IdpMetadata;
import group.mfnr.authorization.flow.persistence.AuthExecutionDefinition;
import group.mfnr.authorization.flow.persistence.AuthFlowDefinition;
import group.mfnr.authorization.security.realm.RealmContextHolder;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E5.4 + federation: the login page renders the configured federation providers, shows the
 * maintenance page under maintenance, and — when the in-flight flow carries an "Identity Provider
 * Redirector" step — either auto-redirects to the broker (REDIRECT) or surfaces the IdP button (OPTION).
 */
class LoginControllerTest {

    private static IdentityProvider stub(final String alias, final String display) {
        return new IdentityProvider() {
            @Override public IdpMetadata metadata() { return IdpMetadata.of(alias, IdpMetadata.Protocol.OIDC, display); }
            @Override public RedirectResponse start(final AuthnRequestContext c) { return new RedirectResponse("/" + alias, java.util.Map.of()); }
            @Override public BrokeredIdentity callback(final CallbackContext c) { return new BrokeredIdentity(alias, "s", null, false, java.util.Map.of()); }
            @Override public void logout(final LogoutContext c) { }
        };
    }

    private final IdentityProviderRegistry registry =
            new IdentityProviderRegistry(List.of(stub("google", "Google"), stub("corp", "Corp SSO")));

    /** An AuthFlowPublisher whose browser flow is a single top-level idp-redirect step (or empty). */
    private static AuthFlowPublisher publisherWith(final AuthFlowDefinition browserFlow) {
        return new AuthFlowPublisher() {
            @Override public AuthFlowDefinition retrieveBrowserFlow(final String realmId) { return browserFlow; }
            @Override public AuthFlowDefinition retrieveFlowForClient(final String realmScopedClientId) { return browserFlow; }
        };
    }

    private static AuthFlowDefinition idpRedirectFlow(final String alias, final String mode) {
        final Map<String, String> config = mode == null ? Map.of("providerAlias", alias)
                : Map.of("providerAlias", alias, "mode", mode);
        return flowWithConfig(config);
    }

    private static AuthFlowDefinition flowWithConfig(final Map<String, String> config) {
        return new AuthFlowDefinition("browser", "master", List.of(
                new AuthExecutionDefinition("e1", null, "idp-redirect", "REQUIRED", false, 10, config)));
    }

    @SuppressWarnings("unchecked")
    private static List<IdpMetadata> providers(final Model model) {
        return (List<IdpMetadata>) model.getAttribute("federationProviders");
    }

    @Test
    void loginPageExposesTheConfiguredFederationProviders() {
        final LoginController controller = new LoginController(false, registry);
        final Model model = new ConcurrentModel();

        final String view = controller.login(model, new MockHttpServletRequest(), new MockHttpServletResponse());

        assertThat(view).isEqualTo("login");
        assertThat(model.getAttribute("federationProviders")).isEqualTo(registry.metadatas());
    }

    @Test
    void maintenanceModeShowsTheMaintenancePage() {
        final LoginController controller = new LoginController(true, registry);

        assertThat(controller.login(new ConcurrentModel(), new MockHttpServletRequest(), new MockHttpServletResponse()))
                .isEqualTo("maintenance");
    }

    @Test
    void redirectModeSkipsLocalLoginAndBouncesToTheBroker() {
        final LoginController controller = new LoginController(false, registry);
        ReflectionTestUtils.setField(controller, "authFlowPublisher",
                publisherWith(idpRedirectFlow("digid", "REDIRECT")));

        final String view = controller.login(new ConcurrentModel(), new MockHttpServletRequest(), new MockHttpServletResponse());

        assertThat(view).isEqualTo("redirect:/broker/digid");
    }

    @Test
    void redirectModeIsContextRelativeSoTheRealmFilterPrefixesItExactlyOnce() {
        // Regression: /login runs under the RealmRoutingFilter's virtual context-path (/realms/{realm}),
        // so Spring MVC already realm-prefixes a "redirect:" view. Pre-prefixing it here too produced
        // /realms/master/realms/master/broker/... — a doubled realm path that 404s. The redirect must be
        // context-relative and let the filter add the realm prefix exactly once.
        final LoginController controller = new LoginController(false, registry);
        ReflectionTestUtils.setField(controller, "authFlowPublisher",
                publisherWith(idpRedirectFlow("digid", "REDIRECT")));
        RealmContextHolder.set("master");
        try {
            assertThat(controller.login(new ConcurrentModel(), new MockHttpServletRequest(), new MockHttpServletResponse()))
                    .isEqualTo("redirect:/broker/digid");
        } finally {
            RealmContextHolder.clear();
        }
    }

    @Test
    void redirectModeIsTheDefaultWhenModeIsUnset() {
        final LoginController controller = new LoginController(false, registry);
        ReflectionTestUtils.setField(controller, "authFlowPublisher",
                publisherWith(idpRedirectFlow("digid", null)));

        assertThat(controller.login(new ConcurrentModel(), new MockHttpServletRequest(), new MockHttpServletResponse()))
                .isEqualTo("redirect:/broker/digid");
    }

    @Test
    void optionModeRendersLocalLoginPlusOnlyTheSelectedProvider() {
        final LoginController controller = new LoginController(false, registry);
        ReflectionTestUtils.setField(controller, "authFlowPublisher",
                publisherWith(idpRedirectFlow("google", "OPTION")));
        final Model model = new ConcurrentModel();

        final String view = controller.login(model, new MockHttpServletRequest(), new MockHttpServletResponse());

        assertThat(view).isEqualTo("login");
        assertThat(providers(model)).extracting(IdpMetadata::alias).containsExactly("google");
    }

    @Test
    void optionModeShowsExactlyTheSelectedProvidersInOrder() {
        final LoginController controller = new LoginController(false, registry);
        ReflectionTestUtils.setField(controller, "authFlowPublisher",
                publisherWith(flowWithConfig(Map.of("mode", "OPTION", "providerAliases", "google,corp"))));
        final Model model = new ConcurrentModel();

        assertThat(controller.login(model, new MockHttpServletRequest(), new MockHttpServletResponse())).isEqualTo("login");
        assertThat(providers(model)).extracting(IdpMetadata::alias).containsExactlyInAnyOrder("google", "corp");
    }

    @Test
    void localOnlyModeRendersLoginWithNoProviderButtons() {
        final LoginController controller = new LoginController(false, registry);
        ReflectionTestUtils.setField(controller, "authFlowPublisher",
                publisherWith(flowWithConfig(Map.of("mode", "LOCAL_ONLY"))));
        final Model model = new ConcurrentModel();

        assertThat(controller.login(model, new MockHttpServletRequest(), new MockHttpServletResponse())).isEqualTo("login");
        assertThat(providers(model)).isEmpty();
    }

    @Test
    void redirectModeDoesNotAutoRedirectOnALoginError() {
        final LoginController controller = new LoginController(false, registry);
        ReflectionTestUtils.setField(controller, "authFlowPublisher",
                publisherWith(idpRedirectFlow("digid", "REDIRECT")));
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("error", "");

        assertThat(controller.login(new ConcurrentModel(), request, new MockHttpServletResponse()))
                .isEqualTo("login");
    }

    @Test
    void noIdpRedirectStepRendersTheNormalLoginPage() {
        final LoginController controller = new LoginController(false, registry);
        ReflectionTestUtils.setField(controller, "authFlowPublisher",
                publisherWith(new AuthFlowDefinition("browser", "master", List.of())));

        assertThat(controller.login(new ConcurrentModel(), new MockHttpServletRequest(), new MockHttpServletResponse()))
                .isEqualTo("login");
    }
}
