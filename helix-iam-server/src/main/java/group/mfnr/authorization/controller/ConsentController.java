package group.mfnr.authorization.controller;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Renders the Helix-branded OAuth consent screen (replacing Spring Authorization Server's default page) for
 * both the authorization-code and RFC 8628 device flows. It shows which app is asking, which permissions it
 * wants in plain language, and — for the device flow — the code the user typed, so they can confirm it matches.
 */
@Controller
public class ConsentController {

    private final RegisteredClientRepository registeredClientRepository;
    private final BrandingSupport brandingSupport;

    public ConsentController(final RegisteredClientRepository registeredClientRepository,
                            final BrandingSupport brandingSupport) {
        this.registeredClientRepository = registeredClientRepository;
        this.brandingSupport = brandingSupport;
    }

    @GetMapping("/oauth2/consent")
    public String consent(final Principal principal, final Model model,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) final String clientId,
                          @RequestParam(OAuth2ParameterNames.SCOPE) final String scope,
                          @RequestParam(OAuth2ParameterNames.STATE) final String state,
                          @RequestParam(name = OAuth2ParameterNames.USER_CODE, required = false) final String userCode) {

        final RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        final String clientName = registeredClient != null && StringUtils.hasText(registeredClient.getClientName())
                ? registeredClient.getClientName() : clientId;

        final List<ScopeView> scopes = new ArrayList<>();
        for (final String requested : StringUtils.delimitedListToStringArray(scope, " ")) {
            if (OidcScopes.OPENID.equals(requested) || !StringUtils.hasText(requested)) {
                continue; // openid is implied, not a user-facing permission
            }
            scopes.add(new ScopeView(requested, describe(requested)));
        }

        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", clientName);
        model.addAttribute("state", state);
        model.addAttribute("scopes", scopes);
        model.addAttribute("principalName", principal != null ? principal.getName() : "");
        model.addAttribute("userCode", userCode);
        // The device flow submits its approval to the device verification endpoint; the code flow to authorize.
        model.addAttribute("requestURI", StringUtils.hasText(userCode) ? "/oauth2/device_verification" : "/oauth2/authorize");
        brandingSupport.apply(model);
        return "consent";
    }

    /** Plain-language description for the scopes we ship; falls back to the scope name. */
    private static String describe(final String scope) {
        return DESCRIPTIONS.getOrDefault(scope, scope);
    }

    private static final Map<String, String> DESCRIPTIONS = new LinkedHashMap<>();
    static {
        DESCRIPTIONS.put("profile", "Your basic profile — name and username");
        DESCRIPTIONS.put("email", "Your email address");
        DESCRIPTIONS.put("offline_access", "Stay signed in — refresh access without signing in again");
        DESCRIPTIONS.put("roles", "Your roles and permissions");
    }

    /** One requested permission, for the template. */
    public record ScopeView(String scope, String description) { }
}
