package io.helixiam.authorization.controller;

import io.helixiam.authorization.amqp.AuthFlowPublisher;
import io.helixiam.authorization.support.RealmScopedKey;
import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.spi.IdpMetadata;
import io.helixiam.authorization.flow.authenticators.IdentityProviderRedirectAuthenticator;
import io.helixiam.authorization.flow.persistence.AuthExecutionDefinition;
import io.helixiam.authorization.flow.persistence.AuthFlowDefinition;
import io.helixiam.authorization.security.captcha.CaptchaService;
import io.helixiam.authorization.security.flow.InFlightClientResolver;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.security.realm.RealmSettingsResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Comparator;
import java.util.List;
import java.util.Map;

@Controller
public class LoginController {

    private final Boolean registerEnabled;
    private final IdentityProviderRegistry identityProviderRegistry;

    // Auth-hardening (feature 5): optional per-realm CAPTCHA gate (field-injected; no-op when provider=none).
    @Autowired(required = false)
    private CaptchaService captchaService;

    // B2: per-realm login theming (field-injected so existing tests that build the controller directly still work).
    @Autowired(required = false)
    private RealmSettingsResolver realmSettingsResolver;

    // Federation: source of the in-flight flow so an "Identity Provider Redirector" step can skip/augment
    // local login (field-injected so existing tests that build the controller directly still work).
    @Autowired(required = false)
    private AuthFlowPublisher authFlowPublisher;

    public LoginController(@Value("${app.maintenance:true}") final boolean registerEnabled,
                           final IdentityProviderRegistry identityProviderRegistry) {
        this.registerEnabled = registerEnabled;
        this.identityProviderRegistry = identityProviderRegistry;
    }

    @GetMapping("/login")
    public String login(final Model model, final HttpServletRequest request, final HttpServletResponse response) {
        if (registerEnabled) {
            return "maintenance";
        }
        final String realm = RealmContextHolder.get();

        // Federation: the in-flight application's single sign-on setting (its bound flow's
        // "Identity Provider Redirector" step) decides how this app federates:
        //   REDIRECT   → skip the local screen and start authentication at the one provider;
        //   OPTION     → show the local form plus exactly the selected provider buttons;
        //   LOCAL_ONLY → show the local form with no provider buttons.
        // With no such step we keep the legacy default: show every enabled provider. Never auto-redirect
        // on a login error (would loop after a failed federation callback bounced back to /login?error).
        final IdpRedirectStep idp = resolveIdpRedirect(realm, request, response);
        final boolean loginError = request.getParameter("error") != null;
        if (idp != null && !loginError
                && IdentityProviderRedirectAuthenticator.MODE_REDIRECT.equals(idp.mode())
                && !idp.aliases().isEmpty()) {
            // Context-relative: /login runs under the RealmRoutingFilter's virtual context-path
            // (/realms/{realm}), which MVC prepends to a "redirect:" view. Pre-prefixing the realm here
            // too would double it (/realms/{realm}/realms/{realm}/broker/... → 404), so let the filter
            // add the realm prefix exactly once — mirroring the LOGIN_ERROR redirect in the broker flow.
            return "redirect:/broker/" + idp.aliases().get(0);
        }

        // Helix IAM E5.4: render a "Sign in with X" link per federation provider the app offers
        // (each points at /broker/{alias}) — app-scoped when its SSO step selects them.
        model.addAttribute("federationProviders", federationProvidersFor(idp));
        // Auth-hardening (feature 5): expose the realm's CAPTCHA provider + site key for the widget.
        final boolean captchaEnabled = captchaService != null && captchaService.isEnabled(realm);
        model.addAttribute("captchaEnabled", captchaEnabled);
        model.addAttribute("captchaProvider", captchaEnabled ? captchaService.providerOf(realm) : "none");
        model.addAttribute("captchaSiteKey", captchaEnabled ? captchaService.siteKey(realm) : null);
        addBranding(model, realm);
        return "login";
    }

    /** B2: expose per-realm branding to the template (null/blank → template falls back to the built-in theme). */
    private void addBranding(final Model model, final String realm) {
        if (realmSettingsResolver == null) {
            return;
        }
        try {
            final RealmSettingsDto s = realmSettingsResolver.get(realm);
            model.addAttribute("brandingLogo", blankToNull(s.logoUrl()));
            model.addAttribute("brandingPrimaryColor", blankToNull(s.primaryColor()));
            model.addAttribute("brandingBackgroundColor", blankToNull(s.backgroundColor()));
            model.addAttribute("brandingWelcomeText", blankToNull(s.welcomeText()));
            model.addAttribute("brandingCustomCss", blankToNull(s.customCss()));
        } catch (final RuntimeException e) {
            // Branding is best-effort: never block login because settings could not be loaded.
        }
    }

    private static String blankToNull(final String v) {
        return v == null || v.isBlank() ? null : v;
    }

    /**
     * The first meaningful top-level {@code idp-redirect} step of the in-flight flow (the in-flight
     * client's bound flow when a client is in play, otherwise the realm's browser flow), or {@code null}
     * when there is none, the flow source is unavailable, or the step neither redirects, lists providers,
     * nor forces local-only. Resolution mirrors {@code FlowLoginSuccessHandler.resolveFlow}; best-effort
     * — never blocks rendering the login page.
     */
    private IdpRedirectStep resolveIdpRedirect(final String realm, final HttpServletRequest request,
                                               final HttpServletResponse response) {
        if (authFlowPublisher == null) {
            return null;
        }
        try {
            final String clientId = InFlightClientResolver.clientId(request, response);
            final AuthFlowDefinition definition = clientId != null && !clientId.isBlank()
                    ? authFlowPublisher.retrieveFlowForClient(RealmScopedKey.pack(realm, clientId))
                    : authFlowPublisher.retrieveBrowserFlow(realm);
            if (definition == null || definition.getExecutions() == null) {
                return null;
            }
            return definition.getExecutions().stream()
                    .filter(e -> e.getParentId() == null
                            && IdentityProviderRedirectAuthenticator.ID.equals(e.getAuthenticatorId()))
                    .sorted(Comparator.comparingInt(AuthExecutionDefinition::getPriority))
                    .map(LoginController::toIdpRedirectStep)
                    .filter(s -> IdentityProviderRedirectAuthenticator.MODE_LOCAL_ONLY.equals(s.mode())
                            || !s.aliases().isEmpty())
                    .findFirst()
                    .orElse(null);
        } catch (final RuntimeException e) {
            // Best-effort: any AMQP/lookup failure just falls back to the normal login page.
            return null;
        }
    }

    private static IdpRedirectStep toIdpRedirectStep(final AuthExecutionDefinition def) {
        final Map<String, String> config = def.getConfig() == null ? Map.of() : def.getConfig();
        final String single = config.get(IdentityProviderRedirectAuthenticator.PROVIDER_ALIAS);
        final String multi = config.get(IdentityProviderRedirectAuthenticator.PROVIDER_ALIASES);
        final String rawMode = config.get(IdentityProviderRedirectAuthenticator.MODE);
        final String mode;
        final List<String> aliases;
        if (IdentityProviderRedirectAuthenticator.MODE_LOCAL_ONLY.equals(rawMode)) {
            mode = IdentityProviderRedirectAuthenticator.MODE_LOCAL_ONLY;
            aliases = List.of();
        } else if (IdentityProviderRedirectAuthenticator.MODE_OPTION.equals(rawMode)) {
            mode = IdentityProviderRedirectAuthenticator.MODE_OPTION;
            aliases = splitAliases(multi != null && !multi.isBlank() ? multi : single);
        } else {
            // Default (and legacy configs) = REDIRECT to the single provider.
            mode = IdentityProviderRedirectAuthenticator.MODE_REDIRECT;
            aliases = splitAliases(single != null && !single.isBlank() ? single : multi);
        }
        return new IdpRedirectStep(mode, aliases);
    }

    private static List<String> splitAliases(final String csv) {
        if (csv == null || csv.isBlank()) {
            return List.of();
        }
        return java.util.Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    /**
     * The federation-provider buttons the login page should show for this request: the app's selected
     * subset in OPTION mode, none in LOCAL_ONLY (or a REDIRECT we did not follow, e.g. after an error),
     * and — with no SSO step configured — every enabled provider (legacy default).
     */
    private List<IdpMetadata> federationProvidersFor(final IdpRedirectStep idp) {
        if (idp == null) {
            return identityProviderRegistry.metadatas();
        }
        if (IdentityProviderRedirectAuthenticator.MODE_LOCAL_ONLY.equals(idp.mode()) || idp.aliases().isEmpty()) {
            return List.of();
        }
        return identityProviderRegistry.metadatas().stream()
                .filter(m -> idp.aliases().contains(m.alias()))
                .toList();
    }

    /** A resolved {@code idp-redirect} step: the SSO mode and the provider aliases it selects. */
    private record IdpRedirectStep(String mode, List<String> aliases) {
    }
}
