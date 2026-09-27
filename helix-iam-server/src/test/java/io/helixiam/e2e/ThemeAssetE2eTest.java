/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import io.helixiam.authorization.theme.asset.AssetFixtures;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Structured theming, fonts and assets (spec §3, §7): {@code POST/GET/DELETE /admin/realms/{r}/theme/assets} with the
 * upload rules and per-realm limits, the anonymous realm-scoped {@code GET /realms/{r}/theme/assets/{id}.{ext}} with
 * its headers, uploaded fonts and images accepted by {@code PUT /theme} only once uploaded, the delete-when-referenced
 * rule (409), permissions, and the export listing asset metadata.
 */
class ThemeAssetE2eTest extends AbstractE2eTest {

    private static final String SVG = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 10 10\">"
            + "<rect width=\"10\" height=\"10\" fill=\"#1f4d47\"/></svg>";
    private static final String SVG_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox";

    private String realm;
    private E2eAdminSession admin;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("assets");
        seed().realm(realm, "Monthfold");
        admin = adminSession(realm);
    }

    private String assets(final String r) {
        return "/admin/realms/" + r + "/theme/assets";
    }

    private E2eHttp.Response uploadFont(final E2eAdminSession who, final String r, final String name, final byte[] bytes) {
        return who.upload(assets(r), Map.of("name", name), "font.woff2", "font/woff2", bytes);
    }

    private E2eHttp.Response uploadImage(final E2eAdminSession who, final String r, final String filename,
                                         final String type, final byte[] bytes) {
        return who.upload(assets(r), Map.of(), filename, type, bytes);
    }

    private static String sha256(final byte[] b) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
    }

    @Test
    void fontsAndImagesAreUploadedListed_andServedAnonymouslyWithSafeHeaders() throws Exception {
        final byte[] font = AssetFixtures.woff2(4096);
        final E2eHttp.Response f = admin.upload(assets(realm), Map.of("name", "Public Sans", "weight", "700"),
                "PublicSans-Bold.woff2", "application/octet-stream", font);
        assertThat(f.status()).as(f.toString()).isEqualTo(201);
        final JsonNode fm = f.json();
        assertThat(fm.path("kind").asText()).isEqualTo("font");
        assertThat(fm.path("name").asText()).isEqualTo("Public Sans");
        assertThat(fm.path("weight").asText()).isEqualTo("700");
        assertThat(fm.path("size").asInt()).isEqualTo(4096);
        assertThat(fm.path("sha256").asText()).isEqualTo(sha256(font));
        assertThat(fm.path("url").asText()).isEqualTo("/realms/" + realm + "/theme/assets/" + fm.path("id").asText() + ".woff2");

        final byte[] svg = SVG.getBytes(StandardCharsets.UTF_8);
        final JsonNode sm = uploadImage(admin, realm, "logo.svg", "image/svg+xml", svg).json();
        final byte[] png = AssetFixtures.png();
        final JsonNode pm = uploadImage(admin, realm, "mark.png", "image/png", png).json();
        final byte[] webp = AssetFixtures.webp();
        final JsonNode wm = uploadImage(admin, realm, "panel.webp", "image/webp", webp).json();

        final JsonNode list = admin.get(assets(realm)).json();
        assertThat(list.isArray()).isTrue();
        assertThat(list).hasSize(4);
        for (final JsonNode e : list) {
            assertThat(e.fieldNames()).toIterable().contains("id", "kind", "name", "ext", "size", "sha256", "created", "url")
                    .doesNotContain("content", "bytes", "realmId");
        }

        final E2eHttp anonymous = newBrowser();
        assertServed(anonymous, fm, font, "font/woff2");
        assertServed(anonymous, pm, png, "image/png");
        assertServed(anonymous, wm, webp, "image/webp");
        final E2eHttp.BytesResponse s = assertServed(anonymous, sm, svg, "image/svg+xml");
        assertThat(s.headers().allValues("Content-Security-Policy")).containsExactly(SVG_CSP);

        // Immutable per id: a revalidation with the ETag is a 304.
        final E2eHttp.BytesResponse again = anonymous.getBytes(sm.path("url").asText(),
                "If-None-Match", "\"" + sm.path("sha256").asText() + "\"");
        assertThat(again.status()).isEqualTo(304);
        assertThat(again.body()).isEmpty();
    }

    private static E2eHttp.BytesResponse assertServed(final E2eHttp browser, final JsonNode meta, final byte[] bytes,
                                                      final String contentType) {
        final E2eHttp.BytesResponse r = browser.getBytes(meta.path("url").asText());
        assertThat(r.status()).as(meta.toString()).isEqualTo(200);
        assertThat(r.body()).isEqualTo(bytes);
        assertThat(r.header("Content-Type").orElseThrow()).isEqualTo(contentType);
        assertThat(r.header("X-Content-Type-Options")).hasValue("nosniff");
        // Review M5: an SVG opened directly is downloaded, never rendered (img/CSS/favicon loads ignore this header).
        final String disposition = "svg".equals(meta.path("ext").asText()) ? "attachment" : "inline";
        assertThat(r.header("Content-Disposition")).hasValue(disposition + "; filename=\"" + meta.path("id").asText()
                + "." + meta.path("ext").asText() + "\"");
        assertThat(r.header("ETag")).hasValue("\"" + meta.path("sha256").asText() + "\"");
        assertThat(r.header("Cache-Control").orElseThrow()).contains("public").contains("max-age=31536000")
                .contains("immutable");
        assertThat(r.headers().allValues("Set-Cookie")).as("a public, cacheable response sets no cookie").isEmpty();
        return r;
    }

    @Test
    void reviewM4_headAnswersHeadersWithoutABody() {
        final JsonNode m = uploadImage(admin, realm, "mark.png", "image/png", AssetFixtures.png()).json();
        final E2eHttp.BytesResponse head = newBrowser().head(m.path("url").asText());
        assertThat(head.status()).isEqualTo(200);
        assertThat(head.body()).isEmpty();
        assertThat(head.header("Content-Type")).hasValue("image/png");
        assertThat(head.header("Content-Length")).hasValue(Integer.toString(AssetFixtures.png().length));
        assertThat(head.header("ETag")).hasValue("\"" + m.path("sha256").asText() + "\"");
        assertThat(head.header("X-Content-Type-Options")).hasValue("nosniff");
        assertThat(head.headers().allValues("Set-Cookie")).isEmpty();
    }

    @Test
    void reviewM4_pathVariantsAreRejected_beforeReachingAnythingButTheAsset() {
        final JsonNode m = uploadImage(admin, realm, "logo.svg", "image/svg+xml", SVG.getBytes(StandardCharsets.UTF_8))
                .json();
        final String id = m.path("id").asText();
        final String base = baseUrl() + "/realms/" + realm + "/theme/assets/";
        final E2eHttp anonymous = newBrowser();
        for (final String variant : List.of(
                base + "../../../admin/realms/" + realm + "/theme/assets",
                base + "..%2F..%2F..%2Fadmin%2Frealms%2F" + realm + "%2Ftheme",
                base + id + ".svg;jsessionid=abc",
                base + ";x=1/" + id + ".svg",
                base + id + "%2Esvg",
                base.replace("/theme/assets/", "/theme//assets/") + id + ".svg",
                base + "/" + id + ".svg",
                base + id + ".svg/",
                base + "x%2F" + id + ".svg",
                base + id + ".svg/..")) {
            final E2eHttp.BytesResponse r = anonymous.getBytes(variant);
            assertThat(r.status()).as(variant).isIn(400, 401, 404);
            assertThat(new String(r.body(), StandardCharsets.UTF_8)).as(variant).doesNotContain("<svg")
                    .doesNotContain("\"id\"");
        }
        assertThat(anonymous.getBytes(m.path("url").asText()).status()).isEqualTo(200);
    }

    @Test
    void uploadsAreCheckedByContentSize_andPerRealmCount() {
        final E2eHttp.Response wrongMagic = uploadFont(admin, realm, "Fake", AssetFixtures.png());
        assertThat(wrongMagic.status()).as(wrongMagic.toString()).isEqualTo(400);
        assertThat(wrongMagic.json().path("fieldErrors").path("file").asText()).contains("woff2");
        final E2eHttp.Response pngThatIsHtml = uploadImage(admin, realm, "logo.png", "image/png",
                "<html><script>alert(1)</script></html>".getBytes(StandardCharsets.UTF_8));
        assertThat(pngThatIsHtml.status()).isEqualTo(400);
        assertThat(uploadImage(admin, realm, "logo.gif", "image/gif", AssetFixtures.png()).status()).isEqualTo(400);

        final E2eHttp.Response tooBig = uploadFont(admin, realm, "Big", AssetFixtures.woff2(500 * 1024 + 1));
        assertThat(tooBig.status()).isEqualTo(400);
        assertThat(tooBig.json().path("fieldErrors").path("file").asText()).contains("500 KB");

        final E2eHttp.Response evil = uploadImage(admin, realm, "logo.svg", "image/svg+xml",
                SVG.replace("<rect", "<script>alert(1)</script><rect").getBytes(StandardCharsets.UTF_8));
        assertThat(evil.status()).isEqualTo(400);
        assertThat(evil.json().path("fieldErrors").path("file").asText()).contains("script");

        final E2eHttp.Response badName = uploadFont(admin, realm, "x\"; } body { color: red", AssetFixtures.woff2(64));
        assertThat(badName.status()).isEqualTo(400);
        assertThat(badName.json().path("fieldErrors").has("name")).isTrue();

        for (int i = 0; i < 8; i++) {
            assertThat(uploadFont(admin, realm, "Font " + i, AssetFixtures.woff2(64)).status()).isEqualTo(201);
        }
        final E2eHttp.Response ninth = uploadFont(admin, realm, "Font 8", AssetFixtures.woff2(64));
        assertThat(ninth.status()).isEqualTo(400);
        assertThat(ninth.json().path("fieldErrors").path("file").asText()).contains("8 fonts");
        assertThat(admin.get(assets(realm)).json()).as("nothing refused was stored").hasSize(8);

        final E2eHttp.Response notMultipart = admin.post(assets(realm), Map.of("name", "x"));
        assertThat(notMultipart.status()).as("not multipart").isEqualTo(415);
    }

    @Test
    void assetsAreRealmScoped_forAdminsAndForThePublicPath() {
        final JsonNode a = uploadImage(admin, realm, "logo.svg", "image/svg+xml", SVG.getBytes(StandardCharsets.UTF_8))
                .json();
        final String id = a.path("id").asText();
        final String other = E2eSeed.unique("rival");
        seed().realm(other);
        final E2eAdminSession adminB = adminSession(other);

        assertThat(newBrowser().getBytes("/realms/" + other + "/theme/assets/" + id + ".svg").status())
                .as("fetched through another realm").isEqualTo(404);
        assertThat(adminB.get(assets(other)).json()).isEmpty();
        assertThat(adminB.delete(assets(other) + "/" + id).status()).as("deleted through another realm").isEqualTo(404);
        assertThat(admin.get(assets(other)).status()).isIn(403, 404);
        assertThat(admin.delete(assets(other) + "/" + id).status()).isIn(403, 404);

        final E2eHttp anonymous = newBrowser();
        assertThat(anonymous.getBytes("/realms/" + realm + "/theme/assets/" + id + ".png").status())
                .as("the extension must match").isEqualTo(404);
        assertThat(anonymous.getBytes("/realms/" + realm + "/theme/assets/" + id).status()).isEqualTo(404);
        assertThat(anonymous.getBytes("/realms/" + realm + "/theme/assets/no-such-id.svg").status()).isEqualTo(404);
        assertThat(anonymous.getBytes("/realms/" + E2eSeed.unique("nope") + "/theme/assets/" + id + ".svg").status())
                .isEqualTo(404);
        assertThat(anonymous.getBytes(a.path("url").asText()).status()).isEqualTo(200);
        // Only the asset path is anonymous: the rest of /theme stays behind authentication.
        assertThat(anonymous.get("/realms/" + realm + "/theme/assets", "Accept", "application/json").status())
                .isNotEqualTo(200);
        assertThat(anonymous.getBytes(assets(realm)).status()).isEqualTo(401);
    }

    @Test
    void theThemeAcceptsUploadedFontsAndImages_onlyOnceTheyExist() {
        final Map<String, Object> theme = Map.of("typography", Map.of("fontSans", "Public Sans",
                "fontDisplay", "Source Serif 4"));
        final E2eHttp.Response before = admin.put("/admin/realms/" + realm + "/theme", theme);
        assertThat(before.status()).as(before.toString()).isEqualTo(400);
        assertThat(before.json().path("fieldErrors").has("typography.fontSans")).isTrue();

        assertThat(uploadFont(admin, realm, "Public Sans", AssetFixtures.woff2(512)).status()).isEqualTo(201);
        assertThat(uploadFont(admin, realm, "Source Serif 4", AssetFixtures.woff2(512)).status()).isEqualTo(201);
        final E2eHttp.Response after = admin.put("/admin/realms/" + realm + "/theme", theme);
        assertThat(after.status()).as(after.toString()).isEqualTo(200);

        final String logo = uploadImage(admin, realm, "logo.svg", "image/svg+xml", SVG.getBytes(StandardCharsets.UTF_8))
                .json().path("url").asText();
        final E2eHttp.Response withLogo = admin.put("/admin/realms/" + realm + "/theme", Map.of(
                "typography", Map.of("fontSans", "Public Sans"), "assets", Map.of("logoUrl", logo, "faviconUrl", logo),
                "customCss", ".helix-brand { background-image: url(" + logo + ") }"));
        assertThat(withLogo.status()).as(withLogo.toString()).isEqualTo(200);

        // Another realm's asset (or a font name another realm uploaded) is not usable here.
        final String other = E2eSeed.unique("other");
        seed().realm(other);
        final E2eAdminSession master = adminSession();
        assertThat(master.put("/admin/realms/" + other + "/theme", Map.of("assets", Map.of("logoUrl", logo)))
                .status()).isEqualTo(400);
        final String foreign = logo.replace("/realms/" + realm + "/", "/realms/" + other + "/");
        assertThat(master.put("/admin/realms/" + other + "/theme", Map.of("assets", Map.of("logoUrl", foreign)))
                .status()).isEqualTo(400);
        assertThat(master.put("/admin/realms/" + other + "/theme", Map.of("typography", Map.of("fontSans", "Public Sans")))
                .status()).isEqualTo(400);
    }

    @Test
    void deletingAnAssetTheThemeStillUses_isRefusedWithTheReferencingFields() {
        final JsonNode font = uploadFont(admin, realm, "Public Sans", AssetFixtures.woff2(512)).json();
        final JsonNode logo = uploadImage(admin, realm, "logo.png", "image/png", AssetFixtures.png()).json();
        final String orgId = admin.post("/admin/realms/" + realm + "/organizations", Map.of("name", E2eSeed.unique("org")))
                .json().path("orgId").asText();
        assertThat(admin.put("/admin/realms/" + realm + "/theme", Map.of("typography", Map.of("fontSans", "Public Sans"),
                "assets", Map.of("logoUrl", logo.path("url").asText()))).status()).isEqualTo(200);
        assertThat(admin.put("/admin/realms/" + realm + "/organizations/" + orgId + "/theme",
                Map.of("assets", Map.of("faviconUrl", logo.path("url").asText()))).status()).isEqualTo(200);

        final E2eHttp.Response refusedFont = admin.delete(assets(realm) + "/" + font.path("id").asText());
        assertThat(refusedFont.status()).as(refusedFont.toString()).isEqualTo(409);
        assertThat(refusedFont.json().path("references")).extracting(JsonNode::asText)
                .containsExactly("theme.typography.fontSans");
        assertThat(refusedFont.json().path("message").asText()).contains("theme.typography.fontSans");
        final E2eHttp.Response refusedLogo = admin.delete(assets(realm) + "/" + logo.path("id").asText());
        assertThat(refusedLogo.status()).isEqualTo(409);
        assertThat(refusedLogo.json().path("references")).extracting(JsonNode::asText).containsExactly(
                "theme.assets.logoUrl", "organizations." + orgId + ".theme.assets.faviconUrl");
        assertThat(newBrowser().getBytes(logo.path("url").asText()).status()).as("still served").isEqualTo(200);

        // Once the themes stop using them, they can go.
        assertThat(admin.put("/admin/realms/" + realm + "/theme", Map.of()).status()).isEqualTo(200);
        assertThat(admin.put("/admin/realms/" + realm + "/organizations/" + orgId + "/theme", Map.of()).status())
                .isEqualTo(200);
        assertThat(admin.delete(assets(realm) + "/" + font.path("id").asText()).status()).isEqualTo(204);
        assertThat(admin.delete(assets(realm) + "/" + logo.path("id").asText()).status()).isEqualTo(204);
        assertThat(admin.delete(assets(realm) + "/" + logo.path("id").asText()).status()).isEqualTo(404);
        assertThat(newBrowser().getBytes(logo.path("url").asText()).status()).isEqualTo(404);
        assertThat(admin.get(assets(realm)).json()).isEmpty();
        assertThat(admin.put("/admin/realms/" + realm + "/theme", Map.of("typography", Map.of("fontSans", "Public Sans")))
                .status()).as("a deleted font no longer validates").isEqualTo(400);
    }

    @Test
    void assetsNeedManageRealm() {
        final E2eAdminSession orgOnly = scopedAdmin("manage-organizations");
        final E2eAdminSession realmOnly = scopedAdmin("manage-realm");
        assertThat(orgOnly.get(assets(realm)).status()).isEqualTo(403);
        assertThat(uploadImage(orgOnly, realm, "logo.png", "image/png", AssetFixtures.png()).status()).isEqualTo(403);
        final E2eHttp.Response ok = uploadImage(realmOnly, realm, "logo.png", "image/png", AssetFixtures.png());
        assertThat(ok.status()).as(ok.toString()).isEqualTo(201);
        assertThat(orgOnly.delete(assets(realm) + "/" + ok.json().path("id").asText()).status()).isEqualTo(403);
        assertThat(realmOnly.get(assets(realm)).json()).hasSize(1);
        assertThat(realmOnly.delete(assets(realm) + "/" + ok.json().path("id").asText()).status()).isEqualTo(204);
    }

    @Test
    void theExportListsAssetMetadata_withoutBytes() {
        final JsonNode font = uploadFont(admin, realm, "Public Sans", AssetFixtures.woff2(512)).json();
        final JsonNode export = admin.get("/admin/realms/" + realm + "/export").json();
        final JsonNode entry = export.path("themeAssets").get(0);
        assertThat(entry.path("id").asText()).isEqualTo(font.path("id").asText());
        assertThat(entry.path("name").asText()).isEqualTo("Public Sans");
        assertThat(entry.path("sha256").asText()).isEqualTo(font.path("sha256").asText());
        assertThat(entry.has("content")).isFalse();
        assertThat(export.path("themeAssets").toString()).doesNotContain("d09GMg"); // base64 of "wOF2"

        // The listing is read-only: the document still imports (here back into the same realm, where the font exists).
        assertThat(admin.put("/admin/realms/" + realm + "/theme", Map.of("typography", Map.of("fontSans", "Public Sans")))
                .status()).isEqualTo(200);
        final JsonNode withTheme = admin.get("/admin/realms/" + realm + "/export").json();
        final E2eHttp.Response imported = adminSession().post("/admin/realms/" + realm + "/import", withTheme);
        assertThat(imported.status()).as(imported.toString()).isEqualTo(200);
    }

    /** A user of {@link #realm} whose only admin permission is {@code permission}, logged in. */
    private E2eAdminSession scopedAdmin(final String permission) {
        final String roleName = E2eSeed.unique("asset-" + permission);
        final E2eHttp.Response role = admin.post("/admin/realms/" + realm + "/roles", Map.of("name", roleName));
        assertThat(role.status()).as(role.toString()).isEqualTo(201);
        String roleId = role.json().path("roleId").asText();
        if (roleId.isBlank()) {
            for (final JsonNode r : admin.get("/admin/realms/" + realm + "/roles").json()) {
                if (roleName.equals(r.path("name").asText())) {
                    roleId = r.path("roleId").asText();
                }
            }
        }
        assertThat(admin.put("/admin/realms/" + realm + "/admin-roles/" + roleId,
                Map.of("permissions", List.of(permission))).status()).isEqualTo(200);
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("scoped"), "Sc0ped-Admin-Passw0rd!");
        assertThat(admin.post("/admin/realms/" + realm + "/users/" + user.userId() + "/roles", Map.of("roleId", roleId))
                .status()).isEqualTo(204);
        return E2eAdminSession.login(newBrowser(), realm, user.username(), user.password());
    }
}
