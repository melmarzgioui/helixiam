/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.render;

import io.helixiam.authorization.controller.ConsentController;
import io.helixiam.authorization.domain.ChangePassword;
import io.helixiam.authorization.domain.UserRegister;
import io.helixiam.authorization.federation.spi.IdpMetadata;
import io.helixiam.authorization.i18n.I18nConfig;
import io.helixiam.authorization.theme.ThemePalette;
import io.helixiam.authorization.theme.EffectiveTheme;
import io.helixiam.authorization.theme.LocalizedList;
import io.helixiam.authorization.theme.LocalizedText;
import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeColor;
import io.helixiam.authorization.theme.ThemeColors;
import io.helixiam.authorization.theme.ThemeAssets;
import io.helixiam.authorization.theme.ThemeDefaults;
import io.helixiam.authorization.theme.ThemeFixtures;
import io.helixiam.authorization.theme.ThemeLayout;
import io.helixiam.authorization.theme.ThemeLinks;
import io.helixiam.authorization.theme.ThemeMerger;
import io.helixiam.authorization.theme.ThemeTexts;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.context.MessageSource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.View;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.spring6.templateresolver.SpringResourceTemplateResolver;
import org.thymeleaf.spring6.view.ThymeleafViewResolver;
import org.thymeleaf.templatemode.TemplateMode;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Spec §2 coverage + §Tests security: EVERY user-facing template (discovered from the classpath, so a new template
 * that does not include the shared theme fragment fails here) is rendered for a realm with a full theme, and must
 * carry the theme stylesheet, favicon, logo and texts, no HelixIAM default wording, and no inline style or script.
 * The same templates rendered with script / attribute-breakout / {@code javascript:} payloads in every theme text
 * and URL field must not execute or break out of anything.
 *
 * <p>Pages that are only reachable mid-flow are rendered through the real Thymeleaf view (the same resolver and view
 * class Spring MVC uses) with a representative model. The HTTP-level checks (login, register, reset, the MFA and
 * consent journey with an organization in context) are in {@code ThemeRenderingE2eTest}.
 */
class ThemedTemplatesTest {

    private static final String REALM = "acme";
    private static final String CONTEXT = "/realms/" + REALM;

    /** Templates that use the split layout (brand panel); all others are card pages. */
    private static final Set<String> SPLIT = Set.of("login", "register/register");

    /** Wording and artwork of the built-in HelixIAM look that a fully themed realm must never show. */
    private static final List<String> DEFAULT_WORDING = List.of("HelixIAM", "Helix IAM", "Helix<b>IAM",
            "helixiam.com", "Secure access for every human and machine", "One identity platform",
            "Self-hosted identity", "OpenID Connect", "helix-favicon.svg", "favicon.avif", "brand-watermark", "kd-spark");

    private static ThymeleafViewResolver views;
    private static GenericWebApplicationContext context;

    @BeforeAll
    static void thymeleaf() {
        final MockServletContext servletContext = new MockServletContext();
        context = new GenericWebApplicationContext(servletContext);
        final MessageSource messages = new I18nConfig().messageSource();
        context.registerBean("messageSource", MessageSource.class, () -> messages);
        context.refresh();
        servletContext.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, context);

        final SpringResourceTemplateResolver templates = new SpringResourceTemplateResolver();
        templates.setApplicationContext(context);
        templates.setPrefix("classpath:/templates/");
        templates.setSuffix(".html");
        templates.setTemplateMode(TemplateMode.HTML);
        templates.setCharacterEncoding("UTF-8");
        templates.setCacheable(true);
        final SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolver(templates);
        engine.setTemplateEngineMessageSource(messages);
        engine.setEnableSpringELCompiler(false);
        views = new ThymeleafViewResolver();
        views.setTemplateEngine(engine);
        views.setApplicationContext(context);
        views.setServletContext(servletContext);
        views.setCharacterEncoding("UTF-8");
    }

    /** Fewer templates than this means discovery is broken (review M7), not that templates were removed. */
    static final int MIN_TEMPLATES = 29;

    /**
     * Every template under {@code templates/} except the fragments — discovered, never listed by hand. Review M7: every
     * copy on the classpath is considered, none may come from test resources (which would shadow the main ones), and
     * finding fewer than {@link #MIN_TEMPLATES} fails the run.
     */
    static Stream<String> templates() throws IOException {
        return discover(new PathMatchingResourcePatternResolver().getResources("classpath*:/templates/**/*.html")).stream();
    }

    static List<String> discover(final Resource[] resources) throws IOException {
        final java.util.TreeSet<String> out = new java.util.TreeSet<>();
        for (final Resource r : resources) {
            final String url = r.getURL().toString();
            assertThat(url).as("a template from test resources would shadow the real one").doesNotContain("/test-classes/");
            final int at = url.lastIndexOf("/templates/");
            final String name = url.substring(at + "/templates/".length(), url.length() - ".html".length());
            if (!name.startsWith("fragments/")) {
                out.add(name);
            }
        }
        assertThat(out).as("templates discovered from the classpath").hasSizeGreaterThanOrEqualTo(MIN_TEMPLATES)
                .contains("login", "register/register", "register/success", "mfa/enable", "mfa/totp",
                        "mfa/recovery-codes", "mfa/webauthn-register", "reset/password", "reset/set", "reset/success",
                        "consent", "activate", "required-actions/acknowledge", "required-actions/update-password",
                        "magic/request", "magic/sent", "magic/confirm", "magic/invalid", "flow/otp-form",
                        "flow/saml-post", "maintenance", "account/index");
        return List.copyOf(out);
    }

    @Test
    void discovery_failsOnTooFewTemplates_orTestResourceCopies() throws Exception {
        final Resource[] real = new PathMatchingResourcePatternResolver().getResources("classpath*:/templates/**/*.html");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> discover(java.util.Arrays.copyOf(real, 5)))
                .isInstanceOf(AssertionError.class).hasMessageContaining("templates discovered");
        final Resource shadow = new org.springframework.core.io.UrlResource(
                "file:/tmp/project/target/test-classes/templates/login.html");
        final Resource[] withShadow = java.util.Arrays.copyOf(real, real.length + 1);
        withShadow[real.length] = shadow;
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> discover(withShadow))
                .isInstanceOf(AssertionError.class).hasMessageContaining("test resources");
    }

    // ------------------------------------------------------------------------------------------------ fixtures

    /** A realm theme that sets every field (the Monthfold reference consumer, plus every asset, text and link). */
    static Theme fullTheme() {
        final Theme m = ThemeFixtures.monthfold();
        return new Theme(m.colors(), m.typography(), m.shape(),
                new ThemeAssets("https://cdn.monthfold.example/logo.svg", "https://cdn.monthfold.example/logo-dark.svg",
                        "https://cdn.monthfold.example/favicon.png", "https://cdn.monthfold.example/panel.webp"),
                new ThemeLayout("split", true, List.of("en", "nl")),
                new ThemeTexts(LocalizedText.of("Monthly reports your clients will actually read."),
                        LocalizedText.of("Bookkeeping for small firms."), LocalizedText.of("Made in Utrecht"),
                        LocalizedText.of("Welcome back to Monthfold."), LocalizedText.of("© Monthfold BV"),
                        LocalizedList.of(List.of("Bank-grade", "EU hosted"))),
                new ThemeLinks("https://monthfold.example/privacy", "https://monthfold.example/terms",
                        "https://monthfold.example/support"), null);
    }

    static ThemePage page(final Theme layer, final String orgName, final String realmDisplayName) {
        final Theme t = ThemePalette.resolve(ThemeMerger.merge(List.of(ThemeDefaults.THEME, layer)));
        return ThemePages.build(new EffectiveTheme(t, "v1", Set.of(), Set.of(), !Theme.EMPTY.equals(layer)), REALM,
                orgName == null ? null : "org-7", orgName, realmDisplayName, Locale.ENGLISH, "abcdef0123456789");
    }

    /** A representative model for every template (mid-flow values included). */
    static Map<String, Object> model(final ThemePage hx) {
        final Map<String, Object> m = new LinkedHashMap<>();
        m.put("hx", hx);
        m.put("_csrf", new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "csrf-token"));
        m.put("errors", new HashMap<String, String>());
        m.put("userRegister", new UserRegister());
        m.put("registerEnabled", true);
        m.put("registrationClaims", List.of());
        m.put("changePassword", new ChangePassword("reset-code"));
        m.put("captchaEnabled", false);
        m.put("captchaProvider", "none");
        m.put("magicLinkEnabled", true);
        m.put("federationProviders", List.of(IdpMetadata.of("corp", IdpMetadata.Protocol.OIDC, "Corporate login")));
        m.put("clientId", "portal");
        m.put("clientName", "Client Portal");
        m.put("state", "st");
        m.put("scopes", List.of(new ConsentController.ScopeView("profile", "Your basic profile")));
        m.put("principalName", "ada");
        m.put("userCode", "");
        m.put("requestURI", "/oauth2/authorize");
        m.put("qrCode", "data:image/png;base64,iVBORw0KGgo=");
        m.put("otpAuthUrl", "otpauth://totp/Monthfold:ada?secret=ABC");
        m.put("secret", "JBSWY3DPEHPK3PXP");
        m.put("skipEnable", true);
        m.put("recoveryCodes", List.of("ABCD-2345", "EFGH-6789"));
        m.put("continueUrl", CONTEXT + "/oauth2/authorize?x=1");
        m.put("challenge", "Y2hhbGxlbmdl");
        m.put("rpId", "localhost");
        m.put("userId", "u1");
        m.put("username", "ada");
        m.put("firstName", "Ada");
        m.put("lastName", "Lovelace");
        m.put("mobilePhone", "-");
        m.put("flowAction", CONTEXT + "/flow");
        m.put("pushNumber", "42");
        m.put("pushId", "p1");
        m.put("qrSessionId", "q1");
        m.put("qrToken", "t1");
        m.put("passkeyLoginChallenge", "Y2hhbGxlbmdl");
        m.put("webauthnChallenge", "Y2hhbGxlbmdl");
        m.put("action", "VERIFY_EMAIL");
        m.put("actionLabel", "Verify your email address");
        m.put("account", new io.helixiam.authorization.controller.account.console.AccountOverview(
                new io.helixiam.authorization.controller.account.console.AccountOverview.Profile("ada", "ada@example.com",
                        false, "Ada", null, null),
                new io.helixiam.authorization.controller.account.console.AccountOverview.TwoStep(true, false, true, 8),
                List.of(new io.helixiam.authorization.controller.account.console.AccountOverview.SessionRow(true,
                                "27 Sep 2026, 14:03 UTC", List.of("web")),
                        new io.helixiam.authorization.controller.account.console.AccountOverview.SessionRow(false,
                                "26 Sep 2026, 09:12 UTC", List.of())),
                true, true));
        m.put("referrer", new io.helixiam.authorization.service.account.AccountReferrer.Link("web", "Client Portal",
                "https://app.monthfold.example/settings"));
        m.put("twoStep", new io.helixiam.authorization.controller.account.console.AccountOverview.TwoStep(true, false, true, 8));
        m.put("email", "ada@example.com");
        m.put("replacing", true);
        m.put("stepUpCode", true);
        m.put("notice", "emailVerified");
        m.put("remaining", 1);
        m.put("token", "magic-token");
        m.put("fields", Map.of("SAMLRequest", "PHNhbWw+"));
        return m;
    }

    static String render(final String template, final Map<String, Object> model) throws Exception {
        return render(template, model, Map.of());
    }

    static String render(final String template, final Map<String, Object> model, final Map<String, String> params)
            throws Exception {
        return render(template, model, params, Locale.ENGLISH);
    }

    static String render(final String template, final Map<String, Object> model, final Map<String, String> params,
                         final Locale locale) throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest(context.getServletContext(), "GET",
                CONTEXT + "/" + template);
        params.forEach(request::addParameter);
        request.setContextPath(CONTEXT);
        request.addPreferredLocale(locale);
        request.setAttribute(DispatcherServlet.WEB_APPLICATION_CONTEXT_ATTRIBUTE, context);
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final View view = views.resolveViewName(template, locale);
        assertThat(view).as(template).isNotNull();
        view.render(new HashMap<>(model), request, response);
        return response.getContentAsString();
    }

    // ------------------------------------------------------------------------------------------------- coverage

    @ParameterizedTest(name = "{0}")
    @MethodSource("templates")
    void everyPage_isFullyThemed_withoutDefaultWordingOrInlineStyle(final String template) throws Exception {
        final String html = render(template, model(page(fullTheme(), null, "Monthfold")));

        assertThat(html).as("theme.css link with ?v=").contains("href=\"" + CONTEXT + "/theme.css?v=abcdef0123456789\"");
        assertThat(html).as("favicon").contains("rel=\"icon\" href=\"https://cdn.monthfold.example/favicon.png\"");
        if (SPLIT.contains(template)) {
            // The brand panel is a dark ground in both schemes: its logo is the dark-ground variant.
            assertThat(html).as("logo").contains("src=\"https://cdn.monthfold.example/logo-dark.svg\"");
        } else {
            assertThat(html).as("logo").contains("src=\"https://cdn.monthfold.example/logo.svg\"")
                    .contains("srcset=\"https://cdn.monthfold.example/logo-dark.svg\"")
                    .contains("media=\"(prefers-color-scheme: dark)\"");
        }
        assertThat(html).as("theme-color").contains("name=\"theme-color\" media=\"(prefers-color-scheme: light)\" content=\"#f7f8f6\"")
                .contains("content=\"#111615\"");
        assertThat(html).as("footer text and links").contains("© Monthfold BV")
                .contains("href=\"https://monthfold.example/privacy\"").contains("href=\"https://monthfold.example/terms\"")
                .contains("href=\"https://monthfold.example/support\"");
        assertThat(html).as("title").containsPattern("<title>Monthfold — [^<]+</title>");
        assertThat(html).as("one page heading (review S1)").containsPattern("<h1[ >]").doesNotContain("<h3");
        if (SPLIT.contains(template)) {
            assertThat(html).contains("Monthly reports your clients will actually read.", "Bookkeeping for small firms.",
                    "Made in Utrecht", "Welcome back to Monthfold.", "Bank-grade", "EU hosted",
                    "src=\"https://cdn.monthfold.example/panel.webp\"", "href=\"" + CONTEXT + "/css/login.css\"");
            assertThat(html).as("no HelixIAM panel art when branded (review B3)").contains("is-branded");
        }
        for (final String wording : DEFAULT_WORDING) {
            assertThat(html).as("default wording: " + wording).doesNotContain(wording);
        }
        assertThat(html).as("no <style>").doesNotContainIgnoringCase("<style");
        assertThat(Pattern.compile("\\sstyle\\s*=", Pattern.CASE_INSENSITIVE).matcher(html).find())
                .as("no style= attribute").isFalse();
        assertThat(Pattern.compile("<script(?![^>]*\\ssrc=)[^>]*>", Pattern.CASE_INSENSITIVE).matcher(html).find())
                .as("no inline <script>").isFalse();
        assertThat(Pattern.compile("\\son[a-z]+\\s*=", Pattern.CASE_INSENSITIVE).matcher(html).find())
                .as("no inline event handlers").isFalse();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("templates")
    void everyPage_withoutATheme_keepsTheBuiltInLook(final String template) throws Exception {
        final String html = render(template, model(page(Theme.EMPTY, null, null)));
        assertThat(html).contains("href=\"" + CONTEXT + "/theme.css?v=abcdef0123456789\"")
                .contains("href=\"" + CONTEXT + "/css/helix.css\"")
                .contains("helix-favicon.svg")
                .contains("Helix<b>IAM</b>");
        assertThat(html).containsPattern("<title>HelixIAM — [^<]+</title>");
        if (SPLIT.contains(template)) {
            assertThat(html).contains("Secure access for every human and machine", "OpenID Connect", "brand-watermark");
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("templates")
    void aBrandedPageWithoutItsOwnFavicon_setsNone_andAnUnthemedPageShowsNoEmptyFooter(final String template)
            throws Exception {
        final Theme noFavicon = new Theme(null, null, null,
                new ThemeAssets("https://cdn.acme.example/logo.svg", null, null, null), null, null, null, null);
        final String branded = render(template, model(page(noFavicon, null, "Acme")));
        assertThat(branded).as("review B2").doesNotContain("rel=\"icon\"").doesNotContain("helix-favicon");
        if (!SPLIT.contains(template)) {
            assertThat(render(template, model(page(Theme.EMPTY, null, null)))).as("review S9").doesNotContain("<footer");
        }
    }

    /**
     * A realm that sets its own theme but no logo is still a branded realm: it shows its own name, never the
     * HelixIAM wordmark, favicon or panel artwork.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("templates")
    void aThemedRealmWithoutALogo_showsItsOwnName_neverTheHelixIamWordmark(final String template) throws Exception {
        final Theme coloursOnly = new Theme(new ThemeColors(new ThemeColor("#1f4d47", null), null, null, null, null,
                null, null, null, null, null, null, null, null, null), null, null, null, null, null, null, null);
        final String html = render(template, model(page(coloursOnly, null, "Acme Accounting")));
        assertThat(html).as("no HelixIAM wordmark").doesNotContain("Helix<b>IAM</b>");
        assertThat(html).as("no HelixIAM favicon").doesNotContain("helix-favicon");
        assertThat(html).as("the realm's own name").contains("Acme Accounting");
    }

    /**
     * A branded split page never falls back to HelixIAM's brand-panel copy: panel texts the customer did not set are
     * hidden (headline, subhead, byline, badges). The HelixIAM copy stays only for the unbranded look.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("templates")
    void aColoursOnlyTheme_showsNoHelixIamBrandPanelCopy(final String template) throws Exception {
        final Theme coloursOnly = new Theme(new ThemeColors(new ThemeColor("#1f4d47", null), null, null, null, null,
                null, null, null, null, null, null, null, null, null), null, null, null, null, null, null, null);
        final String html = render(template, model(page(coloursOnly, null, "Acme Accounting")));
        for (final String helix : List.of("Secure access for every human and machine", "One identity platform",
                "Self-hosted identity", "OpenID Connect", "SAML 2.0", "SCIM", "Passkeys", "brand-badges")) {
            assertThat(html).as(template + ": " + helix).doesNotContain(helix);
        }
    }

    static Stream<String> errorPages() {
        return Stream.of("mfa/totp|code-error", "mfa/enable|code-error", "flow/otp-form|code-error",
                "flow/recovery-code-form|code-error", "reset/set|password-error",
                "required-actions/update-password|password-error", "register/register|password-error");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("errorPages")
    void errorsAreAnnounced_andTiedToTheirFields(final String pageAndId) throws Exception {
        final String template = pageAndId.substring(0, pageAndId.indexOf('|'));
        final String id = pageAndId.substring(pageAndId.indexOf('|') + 1);
        final Map<String, Object> m = model(page(Theme.EMPTY, null, null));
        m.put("error", true);
        final Map<String, Boolean> errors = new HashMap<>();
        errors.put("invalid.password", true);
        m.put("errors", errors);
        final String html = render(template, m);
        assertThat(html).containsPattern("id=\"" + id + "\"[^>]*role=\"alert\"|role=\"alert\"[^>]*id=\"" + id + "\"");
        assertThat(html).containsPattern("aria-invalid=\"true\"[^>]*aria-describedby=\"" + id + "\"");
        final String clean = render(template, model(page(Theme.EMPTY, null, null)));
        assertThat(clean).doesNotContain("aria-invalid").doesNotContain("id=\"" + id + "\"");
    }

    @Test
    void aWrongPassword_isOneFormLevelAlert() throws Exception {
        final String html = render("login", model(page(Theme.EMPTY, null, null)), Map.of("error", "error"));
        assertThat(html).contains("role=\"alert\"").contains("Email or password is incorrect.")
                .containsPattern("id=\"username\"[^>]*aria-invalid=\"true\"[^>]*aria-describedby=\"credentials-error\"")
                .doesNotContain("Provide your");
        final String locked = render("login", model(page(Theme.EMPTY, null, null)), Map.of("error", "accountLocked"));
        assertThat(locked).doesNotContain("Email or password is incorrect.");
    }

    @Test
    void anOrganizationInContext_linksItsThemeCss_andShowsItsName() throws Exception {
        final String html = render("login", model(page(fullTheme(), "Harbor & Pine", "Monthfold")));
        assertThat(html).contains("href=\"" + CONTEXT + "/theme.css?v=abcdef0123456789&amp;org=org-7\"")
                .contains("Sign in to Harbor &amp; Pine").contains("<title>Harbor &amp; Pine — Sign in</title>");
    }

    @Test
    void theCenteredLayout_dropsTheBrandPanel_andPutsTheLogoAboveTheForm() throws Exception {
        final Theme centered = new Theme(null, null, null, new ThemeAssets("https://cdn.acme.example/logo.svg", null, null, null),
                new ThemeLayout("centered", false, List.of("en")), null, null, null);
        final String html = render("login", model(page(centered, null, "Acme")));
        assertThat(html).doesNotContain("helix-brand").contains("is-centered").contains("form-logo")
                .contains("src=\"https://cdn.acme.example/logo.svg\"").doesNotContain("class=\"lang\"");
    }

    // ------------------------------------------------------------------------------------------------------ XSS

    static final List<String> TEXT_PAYLOADS = List.of("<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>",
            "'><svg onload=alert(1)>");
    static final List<String> URL_PAYLOADS = List.of("javascript:alert(1)", "https://x.example/\"><img src=x onerror=alert(1)>",
            "data:text/html,<script>alert(1)</script>", "JaVaScRiPt:alert(1)");

    static Stream<String> xssCases() throws IOException {
        return templates().flatMap(t -> Stream.of(t + "|0", t + "|1", t + "|2"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("xssCases")
    void noThemeTextOrUrl_canInjectScriptOrBreakOutOfAnAttribute(final String templateAndCase) throws Exception {
        final String template = templateAndCase.substring(0, templateAndCase.indexOf('|'));
        final int i = Integer.parseInt(templateAndCase.substring(templateAndCase.indexOf('|') + 1));
        final String text = TEXT_PAYLOADS.get(i);
        final String url = URL_PAYLOADS.get(i);
        final LocalizedText t = LocalizedText.of(text);
        // Unvalidated on purpose: stored rows are validated on write, this checks the rendering itself.
        final Theme evil = new Theme(null, null, null, new ThemeAssets(url, URL_PAYLOADS.get(3), url, url), null,
                new ThemeTexts(t, t, t, t, t, LocalizedList.of(List.of(text))), new ThemeLinks(url, url, url), null);
        final String html = render(template, model(page(evil, text, text)));

        assertThat(html).doesNotContain("<script>alert").doesNotContain("<img src=x").doesNotContain("<svg onload")
                .doesNotContainIgnoringCase("javascript:").doesNotContain("data:text/html");
        assertThat(Pattern.compile("<[a-z]+[^>]*\\son[a-z]+\\s*=", Pattern.CASE_INSENSITIVE).matcher(html).find())
                .as("no element with an event-handler attribute").isFalse();
        assertThat(html).as("the text is shown, escaped").contains(text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;"));
    }
}
