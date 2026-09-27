/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.render;

import io.helixiam.authorization.theme.Theme;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Item A6: every link a user-facing page renders stays inside its realm. The login page's "Create account" link was
 * a bare {@code /register}, which 404s (only {@code /realms/{realm}/…} is served). Every template (discovered from the
 * classpath, like {@link ThemedTemplatesTest}) is rendered for realm {@code acme}; every URL-bearing attribute
 * ({@code href}, {@code src}, {@code action}, {@code formaction}, {@code srcset}, {@code data-href}, {@code data-*-url})
 * must be {@code /realms/acme/…}, an absolute URL of another site ({@code https:}, {@code otpauth:}, a {@code data:}
 * image), a fragment, or a query on the same page ({@code ?lang=nl}). A root-relative path outside the realm, or a page-relative path (which resolves against
 * whatever page it is on), fails. The real-browser crawl is {@code RealmLinksCrawlBrowserE2eTest}.
 */
class RealmRelativeLinksTest {

    private static final String CONTEXT = "/realms/acme/";
    private static final Pattern URL_ATTRIBUTE = Pattern.compile(
            "\\s(href|src|action|formaction|srcset|data-href|data-[a-z-]*url)\\s*=\\s*\"([^\"]*)\"",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern EXTERNAL = Pattern.compile("(?i)(https?://|otpauth:|data:image/|mailto:|tel:).*");

    @BeforeAll
    static void thymeleaf() {
        ThemedTemplatesTest.thymeleaf();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("io.helixiam.authorization.theme.render.ThemedTemplatesTest#templates")
    void everyLinkOnEveryPage_isRealmRelative(final String template) throws Exception {
        final Map<String, Object> model = ThemedTemplatesTest.model(
                ThemedTemplatesTest.page(ThemedTemplatesTest.fullTheme(), "Harbor & Pine", "Monthfold"));
        // The SAML POST-binding page posts to the service provider (another site).
        model.put("action", "flow/saml-post".equals(template) ? "https://sp.example/acs" : "VERIFY_EMAIL");
        final String html = ThemedTemplatesTest.render(template, model);
        assertThat(nonRealmLinks(html)).as(template + ": links outside /realms/acme/").isEmpty();
        final String unthemed = ThemedTemplatesTest.render(template,
                withAction(ThemedTemplatesTest.model(ThemedTemplatesTest.page(Theme.EMPTY, null, null)), template));
        assertThat(nonRealmLinks(unthemed)).as(template + " (no theme): links outside /realms/acme/").isEmpty();
    }

    @Test
    void theCheck_catchesARootRelativeOrPageRelativeLink() {
        assertThat(nonRealmLinks("<a href=\"/register\">x</a><script src=\"/js/App.js\"></script>"
                + "<form action=\"login\"></form><a href=\"/realms/acme/login\">ok</a><a href=\"#main\">ok</a>"
                + "<img src=\"https://cdn.example/x.png\"><a data-poll-url=\"/qr/1\">x</a>"))
                .containsExactly("href=/register", "src=/js/App.js", "action=login", "data-poll-url=/qr/1");
    }

    /**
     * The static scripts run on realm pages: a root-relative URL they build ({@code fetch('/qr/…')},
     * {@code location.href = '/login'}) leaves the realm. They must take their URLs from the page (a
     * {@code data-*-url} attribute the template renders realm-relative).
     */
    @Test
    void noStaticScript_buildsARootRelativeUrl() throws IOException {
        final Pattern rootRelative = Pattern.compile("(fetch\\s*\\(|location(\\.href)?\\s*=|\\.open\\s*\\()\\s*['\"`]/");
        final List<String> offenders = new ArrayList<>();
        for (final Resource js : new PathMatchingResourcePatternResolver().getResources("classpath*:/static/js/**/*.js")) {
            try (InputStream in = js.getInputStream()) {
                final String source = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                final Matcher m = rootRelative.matcher(source);
                while (m.find()) {
                    offenders.add(js.getFilename() + ": " + m.group());
                }
            }
        }
        assertThat(offenders).as("root-relative URLs in static scripts").isEmpty();
    }

    /** Fonts and images in the static stylesheets resolve against the stylesheet (under the realm), never the root. */
    @Test
    void noStaticStylesheet_referencesARootRelativeUrl() throws IOException {
        final Pattern rootRelative = Pattern.compile("url\\(\\s*['\"]?/");
        final List<String> offenders = new ArrayList<>();
        for (final Resource css : new PathMatchingResourcePatternResolver().getResources("classpath*:/static/css/**/*.css")) {
            try (InputStream in = css.getInputStream()) {
                final Matcher m = rootRelative.matcher(new String(in.readAllBytes(), StandardCharsets.UTF_8));
                while (m.find()) {
                    offenders.add(css.getFilename() + ": " + m.group());
                }
            }
        }
        assertThat(offenders).as("root-relative url() in static stylesheets").isEmpty();
    }

    private static Map<String, Object> withAction(final Map<String, Object> model, final String template) {
        model.put("action", "flow/saml-post".equals(template) ? "https://sp.example/acs" : "VERIFY_EMAIL");
        return model;
    }

    /** Every URL attribute that is neither realm-relative, external, nor a fragment ({@code name=value}). */
    static List<String> nonRealmLinks(final String html) {
        final List<String> out = new ArrayList<>();
        final Matcher m = URL_ATTRIBUTE.matcher(html);
        while (m.find()) {
            final String name = m.group(1).toLowerCase(java.util.Locale.ROOT);
            final String value = m.group(2).replace("&amp;", "&").trim();
            if (name.equals("srcset")) {
                for (final String candidate : value.split(",")) {
                    final String url = candidate.trim().split("\\s+")[0];
                    if (!allowed(url)) {
                        out.add(name + "=" + url);
                    }
                }
            } else if (!allowed(value)) {
                out.add(name + "=" + value);
            }
        }
        return out;
    }

    private static boolean allowed(final String url) {
        // "?lang=nl" is the same page with another query (the language switcher).
        return url.isEmpty() || url.startsWith("#") || url.startsWith("?") || url.startsWith(CONTEXT) || EXTERNAL.matcher(url).matches();
    }
}
