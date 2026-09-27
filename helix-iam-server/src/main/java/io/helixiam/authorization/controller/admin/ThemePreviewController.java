/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import com.fasterxml.jackson.databind.JsonNode;
import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import io.helixiam.authorization.security.realm.RealmSettingsResolver;
import io.helixiam.authorization.theme.EffectiveTheme;
import io.helixiam.authorization.theme.ThemeJson;
import io.helixiam.authorization.theme.ThemeService;
import io.helixiam.authorization.theme.render.ThemePage;
import io.helixiam.authorization.theme.render.ThemePages;
import io.helixiam.authorization.theme.render.ThemeStylesheet;
import io.helixiam.authorization.theme.render.ThemeWebConfig;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.thymeleaf.ITemplateEngine;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * {@code POST /admin/realms/{realm}/theme/preview} (spec §7): the login page rendered with a proposed realm theme,
 * without saving it. The body is a theme exactly as for {@code PUT /admin/realms/{realm}/theme} and goes through the
 * same strict parsing and validation ({@code 400 {message, fieldErrors}}). Needs {@code manage-realm} (the
 * {@code theme} route group of {@code AdminRoutePermissions}); not audited, as nothing changes.
 *
 * <h2>Design: the stylesheet travels in the page</h2>
 * A proposed theme has no {@code theme.css} URL, so the generated stylesheet is put in the page as a {@code data:}
 * URL on a {@code <link>} that carries a random per-response nonce, and only this response's CSP allows that nonce
 * ({@code style-src <server> 'nonce-…'}). This keeps the preview stateless — no server-side preview store (which a
 * second instance would not see) and nothing added to the theme or stylesheet caches — and keeps
 * {@code style-src} free of {@code 'unsafe-inline'} (the stylesheet is not written into the page as text either, so
 * nothing is rendered unescaped). The same CSP is repeated in a {@code <meta>} tag and a {@code <base>} points at the
 * server, so the preview holds and loads correctly when the console shows it in an {@code iframe srcdoc};
 * {@code script-src 'none'} and {@code form-action 'none'} make it inert.
 *
 * <h2>No side effects</h2>
 * The page is rendered straight through the template engine against a view of the request that has no session and no
 * CSRF token, so rendering cannot create a session, touch the admin's session or rotate the CSRF cookie; the response
 * is {@code Cache-Control: no-store}.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}")
@Tag(name = "Theme", description = "Structured realm and organization theming")
public class ThemePreviewController {

    private static final Pattern ROOT_RELATIVE_URL = Pattern.compile("url\\(\\s*([\"']?)/(?!/)");
    private static final SecureRandom RANDOM = new SecureRandom();

    private final ThemeService themes;
    private final ThemeStylesheet stylesheets;
    private final ITemplateEngine templates;
    private final ObjectProvider<RealmSettingsResolver> settings;
    private final String publicBaseUrl;

    public ThemePreviewController(final ThemeService themes, final ThemeStylesheet stylesheets,
                                  final ITemplateEngine templates, final ObjectProvider<RealmSettingsResolver> settings,
                                  @org.springframework.beans.factory.annotation.Value("${idp.base.url:}")
                                  final String publicBaseUrl) {
        this.publicBaseUrl = publicBaseUrl;
        this.themes = themes;
        this.stylesheets = stylesheets;
        this.templates = templates;
        this.settings = settings;
    }

    @PostMapping("/theme/preview")
    @Operation(summary = "Render the login page with a proposed realm theme, without saving it")
    public ResponseEntity<String> preview(@PathVariable final String realmId, @RequestBody final JsonNode body,
                                          final HttpServletRequest request, final HttpServletResponse response) {
        if (!themes.realmExists(realmId)) {
            return ResponseEntity.notFound().build();
        }
        final EffectiveTheme effective = themes.previewTheme(realmId, ThemeJson.readStrict(body));
        // Review M6: the configured public origin (idp.base.url), not the Host header, when it is set.
        final String origin = origin(publicBaseUrl, ServletUriComponentsBuilder.fromRequestUri(request)
                .replacePath(null).replaceQuery(null).build().toUriString());
        final ThemeStylesheet.Rendered css = stylesheets.render(effective.theme(),
                stylesheets.fonts(realmId, effective.theme()));
        // Root-relative url()s (the realm's own fonts and images) must name the server: a data: stylesheet has no path.
        final String absolute = ROOT_RELATIVE_URL.matcher(css.css()).replaceAll("url($1" + java.util.regex.Matcher.quoteReplacement(origin) + "/");
        final String nonce = nonce();
        final String csp = policy(origin, nonce, effective);
        final String header = csp + "; frame-ancestors 'self'"; // frame-ancestors is ignored in a <meta> policy
        final Locale locale = LocaleContextHolder.getLocale();
        final ThemePage page = ThemePages.build(effective, realmId, null, null, displayName(realmId), locale,
                css.version()).withPreview(new ThemePage.Preview(
                "data:text/css;base64," + Base64.getEncoder().encodeToString(absolute.getBytes(StandardCharsets.UTF_8)),
                nonce, csp, origin + "/"));

        final Map<String, Object> model = new HashMap<>();
        model.put(ThemeWebConfig.MODEL_ATTRIBUTE, page);
        model.put("federationProviders", List.of());
        model.put("captchaEnabled", false);
        model.put("captchaProvider", "none");
        model.put("magicLinkEnabled", false);
        final WebContext context = new WebContext(JakartaServletWebApplication
                .buildApplication(request.getServletContext()).buildExchange(new IsolatedRequest(request), response),
                locale, model);
        final String html = templates.process("login", context);

        return ResponseEntity.ok()
                .contentType(new MediaType(MediaType.TEXT_HTML, StandardCharsets.UTF_8))
                .cacheControl(CacheControl.noStore())
                .header("Content-Security-Policy", header)
                .header("X-Content-Type-Options", "nosniff")
                .body(html);
    }

    /** The preview's own policy: its stylesheet by nonce, images from the proposed theme's origins, inert. */
    static String policy(final String origin, final String nonce, final EffectiveTheme effective) {
        final StringBuilder img = new StringBuilder(origin).append(" data:");
        new TreeSet<>(effective.imageOrigins()).forEach(o -> img.append(' ').append(o));
        return "default-src 'none'; base-uri " + origin + "; style-src " + origin + " 'nonce-" + nonce + "'; "
                + "img-src " + img + "; font-src " + origin + "; script-src 'none'; form-action 'none'";
    }

    /** The origin of {@code configured} when it is an absolute http(s) URL, else {@code requestOrigin}. */
    static String origin(final String configured, final String requestOrigin) {
        if (configured != null && !configured.isBlank()) {
            try {
                final java.net.URI uri = new java.net.URI(configured.strip());
                if (("https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme()))
                        && uri.getHost() != null) {
                    return uri.getScheme().toLowerCase(Locale.ROOT) + "://" + uri.getHost().toLowerCase(Locale.ROOT)
                            + (uri.getPort() > 0 ? ":" + uri.getPort() : "");
                }
            } catch (final java.net.URISyntaxException ignored) {
                // fall through to the request origin
            }
        }
        return requestOrigin;
    }

    private static String nonce() {
        final byte[] bytes = new byte[18];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String displayName(final String realmId) {
        final RealmSettingsResolver resolver = settings.getIfAvailable();
        final RealmSettingsDto dto = resolver == null ? null : resolver.get(realmId);
        return dto == null ? null : dto.displayName();
    }

    /**
     * The admin request as the template sees it: no session (none is created, the admin's is not read), no CSRF token
     * (so rendering never materialises or rotates one) and no parameters (the page renders in its initial state).
     */
    private static final class IsolatedRequest extends HttpServletRequestWrapper {

        IsolatedRequest(final HttpServletRequest request) {
            super(request);
        }

        @Override
        public HttpSession getSession(final boolean create) {
            return null;
        }

        @Override
        public HttpSession getSession() {
            return null;
        }

        @Override
        public Object getAttribute(final String name) {
            if (CsrfToken.class.getName().equals(name) || "_csrf".equals(name)
                    || (name != null && name.startsWith("org.springframework.security.web.csrf"))) {
                return null;
            }
            return super.getAttribute(name);
        }

        @Override
        public String getParameter(final String name) {
            return null;
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            return Map.of();
        }

        @Override
        public Enumeration<String> getParameterNames() {
            return Collections.emptyEnumeration();
        }

        @Override
        public String[] getParameterValues(final String name) {
            return null;
        }
    }
}
