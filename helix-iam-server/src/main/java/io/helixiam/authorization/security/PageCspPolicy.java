/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.spi.IdpMetadata;
import io.helixiam.authorization.security.captcha.CaptchaService;
import io.helixiam.authorization.security.realm.OrganizationContext;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.theme.ThemeService;
import io.helixiam.authorization.theme.ThemeUrls;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * The Content-Security-Policy of the server-rendered pages (security review M3, tightened by structured theming §6).
 *
 * <ul>
 *   <li>{@code style-src 'self'} — no {@code 'unsafe-inline'}: the pages carry no {@code <style>} blocks and no
 *       {@code style=""} attributes; realm styling comes from {@code /realms/{realm}/theme.css} (same origin).</li>
 *   <li>{@code img-src 'self' data:} plus, per realm and per request, the realm's (and the organization in
 *       context's) allowlisted image origins — the operator allowlist and the https origins of the theme's own image
 *       URLs ({@link io.helixiam.authorization.theme.EffectiveTheme#imageOrigins()}) — and the origins of the
 *       realm's identity-provider button logos. Outside a realm (no realm-routed request) it is {@code 'self' data:}.</li>
 *   <li>{@code script-src}/{@code frame-src}/{@code connect-src} add the CAPTCHA provider's hosts only when the
 *       realm enables CAPTCHA (Cloudflare Turnstile or Google reCAPTCHA).</li>
 *   <li>{@code form-action 'self'} plus, per request (item A1), the origins of the redirect URIs registered for the
 *       client of the pending authorization request — the request saved in the session while the user signs in, or
 *       the {@code client_id} of the consent page — and, on the end-session (logout) pages, the client's post-logout
 *       redirect origins. Browsers apply {@code form-action} to every redirect after a form POST, so without them
 *       {@code POST /login} (or {@code /mfa/totp}) → {@code 302 /oauth2/authorize} → {@code 302 https://app/callback}
 *       is blocked. Only origins of URIs the client registered are added (never the request's own
 *       {@code redirect_uri}), so a page can at most post to where the authorization server would redirect anyway.</li>
 *   <li>SAML POST-binding pages allow {@code form-action https:} (the auto-submit goes to the peer).</li>
 * </ul>
 * Any lookup failure falls back to the realm-less policy (never to a looser one).
 */
@Component
public class PageCspPolicy {

    static final String TURNSTILE = "https://challenges.cloudflare.com";
    static final List<String> RECAPTCHA_SCRIPTS = List.of("https://www.google.com", "https://www.gstatic.com");
    static final String RECAPTCHA_FRAME = "https://www.google.com";

    private final ObjectProvider<ThemeService> themes;
    private final ObjectProvider<CaptchaService> captcha;
    private final ObjectProvider<IdentityProviderRegistry> identityProviders;
    private final ObjectProvider<RegisteredClientRepository> clients;

    /** Spring Security's session key of the saved (pending) request, as {@code HttpSessionRequestCache} writes it. */
    static final String SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";
    private static final Pattern HOST = Pattern.compile("[a-z0-9.-]{1,253}|\\[[0-9a-f:.]{2,45}]");
    private static final Pattern SCHEME = Pattern.compile("[a-z][a-z0-9+.-]{0,62}");
    /** Schemes that must never become a {@code form-action} source. */
    private static final Set<String> UNSAFE_SCHEMES = Set.of("javascript", "data", "blob", "filesystem", "file",
            "about", "vbscript");

    public PageCspPolicy(final ObjectProvider<ThemeService> themes, final ObjectProvider<CaptchaService> captcha,
                         final ObjectProvider<IdentityProviderRegistry> identityProviders,
                         final ObjectProvider<RegisteredClientRepository> clients) {
        this.themes = themes;
        this.captcha = captcha;
        this.identityProviders = identityProviders;
        this.clients = clients;
    }

    /** The policy for a page request; {@code saml} relaxes {@code form-action} for the POST-binding pages. */
    public String policy(final HttpServletRequest request, final boolean saml) {
        final String realm = RealmContextHolder.get();
        if (realm == null) {
            return build(Set.of(), null, saml);
        }
        final Set<String> formTargets = formActionOrigins(request);
        try {
            final Set<String> images = new TreeSet<>();
            final ThemeService service = themes.getIfAvailable();
            if (service != null) {
                images.addAll(service.effectiveTheme(realm, OrganizationContext.current(request, realm)).imageOrigins());
            }
            final IdentityProviderRegistry registry = identityProviders.getIfAvailable();
            if (registry != null) {
                for (final IdpMetadata idp : registry.metadatas()) {
                    final String origin = ThemeUrls.httpsOrigin(idp.logoUrl());
                    if (origin != null) {
                        images.add(origin);
                    }
                }
            }
            final CaptchaService captchaService = captcha.getIfAvailable();
            final String provider = captchaService != null && captchaService.isEnabled(realm)
                    ? captchaService.providerOf(realm) : null;
            return build(images, provider, saml, formTargets);
        } catch (final RuntimeException e) {
            return build(Set.of(), null, saml, formTargets);
        }
    }

    /**
     * Item A1: the redirect origins a form on this page may end up at — the registered redirect URIs of the client of
     * the pending authorization request (the consent page names it in {@code client_id}; every other page finds it in
     * the request saved in the session) and, on the end-session endpoint, the client's post-logout redirect URIs.
     * Empty when there is no such client; never throws.
     */
    Set<String> formActionOrigins(final HttpServletRequest request) {
        final Set<String> origins = new TreeSet<>();
        try {
            final RegisteredClientRepository repository = clients.getIfAvailable();
            if (repository == null || request == null) {
                return origins;
            }
            final String path = request.getServletPath();
            final boolean logout = "/connect/logout".equals(path);
            String clientId = null;
            if (logout || "/oauth2/consent".equals(path) || "/oauth2/authorize".equals(path)) {
                clientId = request.getParameter("client_id");
            }
            if (clientId == null && !logout) {
                clientId = pendingAuthorizationClientId(request);
            }
            if (clientId == null || clientId.isBlank()) {
                return origins;
            }
            final RegisteredClient client = repository.findByClientId(clientId);
            if (client == null) {
                return origins;
            }
            for (final String uri : logout ? client.getPostLogoutRedirectUris() : client.getRedirectUris()) {
                final String source = formActionSource(uri);
                if (source != null) {
                    origins.add(source);
                }
            }
        } catch (final RuntimeException e) {
            origins.clear(); // fail closed: 'self' only
        }
        return origins;
    }

    /** The {@code client_id} of the authorization request saved in the session (never creates a session). */
    private static String pendingAuthorizationClientId(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        if (session == null || !(session.getAttribute(SAVED_REQUEST) instanceof SavedRequest saved)) {
            return null;
        }
        final String url = saved.getRedirectUrl();
        if (url == null || !URI.create(url).getPath().endsWith("/oauth2/authorize")) {
            return null;
        }
        final String[] ids = saved.getParameterValues("client_id");
        return ids != null && ids.length == 1 ? ids[0] : null;
    }

    /**
     * The CSP source expression that allows a form POST to be redirected to {@code redirectUri}: its origin
     * ({@code scheme://host[:port]}, default port dropped) for http(s), or just {@code scheme:} for a native app's
     * private-use scheme (RFC 8252). Null for relative, wildcard, unparsable or script-capable URIs, or anything
     * that could smuggle another directive into the header.
     */
    static String formActionSource(final String redirectUri) {
        if (redirectUri == null || redirectUri.isBlank() || redirectUri.length() > 2048
                || redirectUri.chars().anyMatch(c -> c <= 0x20 || c == ';' || c == ',' || c == '\'' || c == '*' || c >= 0x7f)) {
            return null;
        }
        final URI uri;
        try {
            uri = new URI(redirectUri);
        } catch (final URISyntaxException e) {
            return null;
        }
        final String scheme = uri.getScheme() == null ? null : uri.getScheme().toLowerCase(Locale.ROOT);
        if (scheme == null || !SCHEME.matcher(scheme).matches() || UNSAFE_SCHEMES.contains(scheme)) {
            return null;
        }
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            return scheme + ":";
        }
        final String host = uri.getHost() == null ? null : uri.getHost().toLowerCase(Locale.ROOT);
        if (host == null || !HOST.matcher(host).matches()) {
            return null;
        }
        final int port = uri.getPort();
        final boolean defaultPort = port == -1 || ("https".equals(scheme) && port == 443) || ("http".equals(scheme) && port == 80);
        return scheme + "://" + host + (defaultPort ? "" : ":" + port);
    }
    /**
     * The policy text.
     *
     * @param imageOrigins    extra https origins for {@code img-src} (already normalised {@code https://host[:port]})
     * @param captchaProvider {@code turnstile}, {@code recaptcha}, or null when CAPTCHA is off
     */
    static String build(final Collection<String> imageOrigins, final String captchaProvider, final boolean saml) {
        return build(imageOrigins, captchaProvider, saml, Set.of());
    }

    /**
     * The policy text, with {@code formActionOrigins} (source expressions from {@link #formActionSource}) added to
     * {@code form-action} on non-SAML pages. Anything that is not such a source expression is dropped.
     */
    static String build(final Collection<String> imageOrigins, final String captchaProvider, final boolean saml,
                        final Collection<String> formActionOrigins) {
        final StringBuilder form = new StringBuilder("'self'");
        if (saml) {
            form.append(" https:");
        } else {
            new TreeSet<>(formActionOrigins).stream()
                    .filter(o -> o != null && o.equals(formActionSource(o.endsWith(":") ? o + "/x" : o)))
                    .forEach(o -> form.append(' ').append(o));
        }
        final StringBuilder img = new StringBuilder("'self' data:");
        new TreeSet<>(imageOrigins).stream()
                .filter(o -> o != null && ThemeUrls.normalizeOrigin(o) != null && ThemeUrls.normalizeOrigin(o).equals(o))
                .forEach(o -> img.append(' ').append(o));
        final StringBuilder script = new StringBuilder("'self'");
        final StringBuilder connect = new StringBuilder("'self'");
        String frame = "'none'";
        if ("turnstile".equals(captchaProvider)) {
            script.append(' ').append(TURNSTILE);
            connect.append(' ').append(TURNSTILE);
            frame = TURNSTILE;
        } else if ("recaptcha".equals(captchaProvider)) {
            RECAPTCHA_SCRIPTS.forEach(h -> script.append(' ').append(h));
            frame = RECAPTCHA_FRAME;
        }
        return "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; "
                + "img-src " + img + "; font-src 'self'; style-src 'self'; "
                + "script-src " + script + "; frame-src " + frame + "; connect-src " + connect + "; "
                + "form-action " + form;
    }

    /**
     * Item 6: the page policy with {@code frame-src} set to the http(s) origins of {@code frameUrls} (the OIDC
     * front-channel logout page loads each client's logout URL in a hidden iframe; every other page has
     * {@code frame-src 'none'}). URLs that are not plain http(s) origins are left out; none left gives {@code 'none'}.
     */
    public String withFrames(final HttpServletRequest request, final Collection<String> frameUrls) {
        final Set<String> origins = new TreeSet<>();
        if (frameUrls != null) {
            for (final String url : frameUrls) {
                final String source = formActionSource(url);
                if (source != null && (source.startsWith("https://") || source.startsWith("http://"))) {
                    origins.add(source);
                }
            }
        }
        final String policy = policy(request, false);
        final int start = policy.indexOf("frame-src ");
        final int end = start < 0 ? -1 : policy.indexOf(';', start);
        if (start < 0 || end < 0) {
            return policy;
        }
        return policy.substring(0, start) + "frame-src " + (origins.isEmpty() ? "'none'" : String.join(" ", origins))
                + policy.substring(end);
    }

    /** A header writer for the page responses; a CSP the handler already set (e.g. on theme assets) is kept. */
    public HeaderWriter headerWriter(final boolean saml) {
        return (final HttpServletRequest request, final HttpServletResponse response) -> {
            if (!response.containsHeader("Content-Security-Policy")) {
                response.setHeader("Content-Security-Policy", policy(request, saml));
            }
        };
    }
}
