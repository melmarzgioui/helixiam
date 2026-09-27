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
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

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

    public PageCspPolicy(final ObjectProvider<ThemeService> themes, final ObjectProvider<CaptchaService> captcha,
                         final ObjectProvider<IdentityProviderRegistry> identityProviders) {
        this.themes = themes;
        this.captcha = captcha;
        this.identityProviders = identityProviders;
    }

    /** The policy for a page request; {@code saml} relaxes {@code form-action} for the POST-binding pages. */
    public String policy(final HttpServletRequest request, final boolean saml) {
        final String realm = RealmContextHolder.get();
        if (realm == null) {
            return build(Set.of(), null, saml);
        }
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
            return build(images, provider, saml);
        } catch (final RuntimeException e) {
            return build(Set.of(), null, saml);
        }
    }

    /**
     * The policy text.
     *
     * @param imageOrigins    extra https origins for {@code img-src} (already normalised {@code https://host[:port]})
     * @param captchaProvider {@code turnstile}, {@code recaptcha}, or null when CAPTCHA is off
     */
    static String build(final Collection<String> imageOrigins, final String captchaProvider, final boolean saml) {
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
                + "form-action " + (saml ? "'self' https:" : "'self'");
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
