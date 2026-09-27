/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.theme.asset.AssetFixtures;
import io.helixiam.authorization.theme.file.FileThemeRegistry;
import io.helixiam.testsupport.LogCapture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * File themes (structured theming spec §5) over real HTTP: a theme mounted in {@code helix.theme.directory} and
 * selected by a realm is its base layer (database fields override it); its files are served under the realm's asset
 * path with the upload rules and headers; an invalid theme is refused with a log and the realm falls back; and a
 * file theme renders exactly the theme.css of the same theme stored through the admin API.
 */
class FileThemeE2eTest extends AbstractE2eTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SVG = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 10 10\">"
            + "<rect width=\"10\" height=\"10\" fill=\"#1f4d47\"/></svg>";
    private static final String SVG_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox";
    private static final Pattern FILE_ASSET = Pattern.compile("/realms/[^/\"]+/theme/assets/(ft-[0-9a-f]{40})\\.(svg|woff2)");

    private String realm;
    private E2eAdminSession admin;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("filetheme");
        seed().realm(realm, "Monthfold");
        admin = adminSession(realm);
    }

    private FileThemeRegistry registry() {
        return context.getBean(FileThemeRegistry.class);
    }

    private static Map<String, Object> monthfold() {
        final Map<String, Object> t = new HashMap<>();
        t.put("colors", Map.of("primary", Map.of("light", "#1f4d47", "dark", "#7fb8ac"),
                "surface", Map.of("light", "#f7f8f6", "dark", "#111615"),
                "ink", Map.of("light", "#16211f", "dark", "#e8eeec")));
        t.put("shape", Map.of("radius", 6));
        t.put("layout", Map.of("layout", "split", "showLanguageSwitcher", false, "supportedLocales", List.of("en")));
        t.put("texts", Map.of("brandHeadline", "Monthly reports your clients will actually read.",
                "welcomeText", "Welcome back."));
        t.put("links", Map.of("privacyUrl", "https://monthfold.example/privacy"));
        return t;
    }

    /** Writes {@code THEMES_DIR/name} (theme.json, and a logo plus a font when {@code withAssets}). */
    private static String writeTheme(final String name, final Map<String, Object> theme, final boolean withAssets)
            throws IOException {
        final Path dir = Files.createDirectories(THEMES_DIR.resolve(name));
        final Map<String, Object> t = new HashMap<>(theme);
        if (withAssets) {
            t.put("assets", Map.of("logoUrl", "assets/logo.svg"));
            t.put("typography", Map.of("fontSans", "Brand Sans"));
            Files.createDirectories(dir.resolve("assets"));
            Files.writeString(dir.resolve("assets/logo.svg"), SVG);
            Files.write(dir.resolve("assets/BrandSans.woff2"), AssetFixtures.woff2(4096));
            Files.writeString(dir.resolve("fonts.json"),
                    "[{\"file\": \"BrandSans.woff2\", \"family\": \"Brand Sans\", \"weight\": \"100 900\"}]");
        }
        Files.writeString(dir.resolve("theme.json"), JSON.writeValueAsString(t));
        return name;
    }

    private E2eHttp.Response select(final String name) {
        final Map<String, Object> body = new HashMap<>();
        body.put("themeName", name);
        return admin.put("/admin/realms/" + realm + "/theme/base", body);
    }

    private String css(final String r) {
        final E2eHttp.Response css = newBrowser().get("/realms/" + r + "/theme.css");
        assertThat(css.status()).as(css.toString()).isEqualTo(200);
        return css.body();
    }

    @Test
    void aMountedThemeIsUsed_itsFilesAreServedUnderTheRealm_andDatabaseFieldsOverrideIt() throws IOException {
        final String name = writeTheme(E2eSeed.unique("monthfold"), monthfold(), true);
        assertThat(registry().reload().get(name).problems()).isEmpty();

        final E2eHttp.Response selected = select(name);
        assertThat(selected.status()).as(selected.toString()).isEqualTo(200);
        assertThat(selected.json().path("status").asText()).isEqualTo("active");
        assertThat(selected.json().path("themeName").asText()).isEqualTo(name);

        final String css = css(realm);
        assertThat(css).contains("--hx-primary: #1f4d47;", "--hx-radius: 6px;", "font-family: \"Brand Sans\"");
        final Matcher font = FILE_ASSET.matcher(css);
        assertThat(font.find()).as("the file theme's font is served under the realm: " + css).isTrue();
        assertThat(font.group()).startsWith("/realms/" + realm + "/theme/assets/").endsWith(".woff2");

        final String login = newBrowser().get("/realms/" + realm + "/login", "Accept", "text/html").body();
        final Matcher logo = FILE_ASSET.matcher(login);
        assertThat(logo.find()).as("the file theme's logo on the sign-in page").isTrue();
        assertThat(logo.group()).startsWith("/realms/" + realm + "/theme/assets/").endsWith(".svg");
        assertThat(login).contains("Monthly reports your clients will actually read.");

        // The logo is served with the same rules and headers as an uploaded SVG.
        final E2eHttp.BytesResponse svg = newBrowser().getBytes(logo.group());
        assertThat(svg.status()).isEqualTo(200);
        assertThat(new String(svg.body(), StandardCharsets.UTF_8)).isEqualTo(SVG);
        assertThat(svg.header("Content-Type")).hasValue("image/svg+xml");
        assertThat(svg.header("X-Content-Type-Options")).hasValue("nosniff");
        assertThat(svg.headers().allValues("Content-Security-Policy")).containsExactly(SVG_CSP);
        assertThat(svg.header("Content-Disposition").orElseThrow()).startsWith("attachment;");
        assertThat(svg.header("Set-Cookie")).isEmpty();
        // ...only under the realm that selected the theme.
        final String other = E2eSeed.unique("nofile");
        seed().realm(other);
        assertThat(newBrowser().getBytes(logo.group().replace("/realms/" + realm + "/", "/realms/" + other + "/"))
                .status()).isEqualTo(404);

        // Database fields override the file's values, field by field.
        final E2eHttp.Response override = admin.put("/admin/realms/" + realm + "/theme",
                Map.of("colors", Map.of("primary", Map.of("light", "#6d28d9")),
                        "typography", Map.of("fontDisplay", "Brand Sans")));
        assertThat(override.status()).as("a database layer may use the file theme's font: " + override).isEqualTo(200);
        assertThat(css(realm)).contains("--hx-primary: #6d28d9;", "--hx-radius: 6px;");

        // Clearing the selection drops the file layer; the database layer stays.
        assertThat(select(null).json().path("status").asText()).isEqualTo("none");
        assertThat(css(realm)).contains("--hx-primary: #6d28d9;").doesNotContain("--hx-radius: 6px;");
        assertThat(newBrowser().getBytes(logo.group()).status()).isEqualTo(404);
    }

    @Test
    void anInvalidThemeIsRefusedWithALog_andTheRealmFallsBack() throws IOException {
        final String name = writeTheme(E2eSeed.unique("fallback"), monthfold(), true);
        registry().reload();
        assertThat(select(name).status()).isEqualTo(200);
        assertThat(admin.put("/admin/realms/" + realm + "/theme", Map.of("shape", Map.of("radius", 10))).status())
                .isEqualTo(200);
        assertThat(css(realm)).contains("--hx-primary: #1f4d47;", "--hx-radius: 10px;");

        // The operator breaks the theme (a colour that is not #RRGGBB, and a script in the logo).
        final Map<String, Object> broken = monthfold();
        broken.put("colors", Map.of("primary", Map.of("light", "teal")));
        writeTheme(name, broken, true);
        Files.writeString(THEMES_DIR.resolve(name).resolve("assets/logo.svg"),
                "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>");
        try (LogCapture log = LogCapture.of(FileThemeRegistry.class)) {
            registry().reload();
            assertThat(log.text()).contains("File theme " + name + " is refused")
                    .contains("colors.primary.light").contains("assets/logo.svg");
            // The realm that selected it: database theme over the default, and a clear warning.
            final String css = css(realm);
            assertThat(css).contains("--hx-radius: 10px;").doesNotContain("#1f4d47");
            assertThat(log.text()).contains("Realm " + realm + " selects file theme " + name);
        }
        assertThat(newBrowser().get("/realms/" + realm + "/login", "Accept", "text/html").status()).isEqualTo(200);

        final JsonNode base = admin.get("/admin/realms/" + realm + "/theme/base").json();
        assertThat(base.path("status").asText()).isEqualTo("refused");
        final JsonNode listed = findByName(base.path("available"), name);
        assertThat(listed.path("valid").asBoolean()).isFalse();
        assertThat(listed.path("problems").toString()).contains("colors.primary.light");

        // A refused or unknown theme cannot be selected.
        final E2eHttp.Response refused = select(name);
        assertThat(refused.status()).isEqualTo(400);
        assertThat(refused.json().path("fieldErrors").has("themeName")).isTrue();
        assertThat(select("no-such-theme").status()).isEqualTo(400);
        assertThat(admin.put("/admin/realms/" + realm + "/theme/base", Map.of("themeNme", "x")).status()).isEqualTo(400);

        // Fixing the files brings it back on the next reload.
        writeTheme(name, monthfold(), true);
        registry().reload();
        assertThat(css(realm)).contains("--hx-primary: #1f4d47;");
    }

    @Test
    void aFileThemeRendersTheSameThemeCss_asTheSameThemeStoredThroughTheApi() throws IOException {
        final String name = writeTheme(E2eSeed.unique("same"), monthfold(), false);
        registry().reload();
        assertThat(select(name).status()).isEqualTo(200);

        final String apiRealm = E2eSeed.unique("apitheme");
        seed().realm(apiRealm, "Monthfold");
        assertThat(adminSession(apiRealm).put("/admin/realms/" + apiRealm + "/theme", monthfold()).status()).isEqualTo(200);

        final E2eHttp.Response fromFile = newBrowser().get("/realms/" + realm + "/theme.css");
        final E2eHttp.Response fromApi = newBrowser().get("/realms/" + apiRealm + "/theme.css");
        assertThat(fromFile.body()).contains("--hx-primary: #1f4d47;").isEqualTo(fromApi.body());
        assertThat(fromFile.header("ETag")).isEqualTo(fromApi.header("ETag"));
    }

    @Test
    void aFontTheFileThemeAlsoProvides_canBeDeletedFromTheUploads_andSelectionIsScopedToThePathRealm()
            throws IOException {
        final String name = writeTheme(E2eSeed.unique("fonts"), monthfold(), true);
        registry().reload();
        final String assets = "/admin/realms/" + realm + "/theme/assets";
        final E2eHttp.Response uploaded = admin.upload(assets, Map.of("name", "Brand Sans", "weight", "700"),
                "font.woff2", "font/woff2", AssetFixtures.woff2(2048));
        assertThat(uploaded.status()).as(uploaded.toString()).isEqualTo(201);
        final String fontId = uploaded.json().path("id").asText();
        assertThat(admin.put("/admin/realms/" + realm + "/theme", Map.of("typography", Map.of("fontSans", "Brand Sans")))
                .status()).isEqualTo(200);

        // Without the file theme, the upload is the family's last file: deleting it would break the theme.
        final E2eHttp.Response blocked = admin.delete(assets + "/" + fontId);
        assertThat(blocked.status()).isEqualTo(409);
        assertThat(blocked.json().path("references").toString()).contains("theme.typography.fontSans");

        // With the file theme, the family keeps resolving from the theme's own font.
        assertThat(select(name).status()).isEqualTo(200);
        assertThat(admin.delete(assets + "/" + fontId).status()).isEqualTo(204);
        assertThat(css(realm)).contains("font-family: \"Brand Sans\"");

        // Another realm's admin cannot read or change this realm's selection.
        final String other = E2eSeed.unique("othertheme");
        seed().realm(other);
        final E2eAdminSession otherAdmin = adminSession(other);
        assertThat(otherAdmin.get("/admin/realms/" + realm + "/theme/base").status()).isIn(403, 404);
        assertThat(otherAdmin.put("/admin/realms/" + realm + "/theme/base", Map.of("themeName", name)).status())
                .isIn(403, 404);
        assertThat(admin.get("/admin/realms/no-such-realm-x/theme/base").status()).isIn(403, 404);
    }

    private static JsonNode findByName(final JsonNode array, final String name) {
        for (final JsonNode n : array) {
            if (name.equals(n.path("name").asText())) {
                return n;
            }
        }
        throw new AssertionError("no " + name + " in " + array);
    }
}
