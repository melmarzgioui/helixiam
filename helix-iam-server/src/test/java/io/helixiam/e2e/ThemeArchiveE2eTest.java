/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.helixiam.authorization.theme.asset.AssetFixtures;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Review I2 (spec §7, "asset bytes go in an optional archive export"): {@code GET /export?includeAssets=true} returns a
 * zip with the document, a manifest and the asset bytes; importing it re-uploads every asset through the normal upload
 * rules (sha256 checked against the manifest), rewrites asset URLs to the target realm's new ids, then imports the
 * document as usual. The plain JSON import is unchanged.
 */
class ThemeArchiveE2eTest extends AbstractE2eTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SVG = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 10 10\">"
            + "<rect width=\"10\" height=\"10\" fill=\"#1f4d47\"/></svg>";

    private String realm;
    private E2eAdminSession admin;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("arch");
        seed().realm(realm, "Monthfold");
        admin = adminSession(realm);
    }

    private static Map<String, byte[]> unzip(final byte[] zip) throws IOException {
        final Map<String, byte[]> out = new LinkedHashMap<>();
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                out.put(e.getName(), z.readAllBytes());
            }
        }
        return out;
    }

    private static byte[] zip(final Map<String, byte[]> entries) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(out)) {
            for (final Map.Entry<String, byte[]> e : entries.entrySet()) {
                z.putNextEntry(new ZipEntry(e.getKey()));
                z.write(e.getValue());
                z.closeEntry();
            }
        }
        return out.toByteArray();
    }

    @Test
    void anArchiveRoundTripsIntoAnotherRealm_withAssetsReUploadedAndUrlsRewritten() throws Exception {
        final String assets = "/admin/realms/" + realm + "/theme/assets";
        final JsonNode font = admin.upload(assets, Map.of("name", "Public Sans"), "PublicSans.woff2", "font/woff2",
                AssetFixtures.woff2(2048)).json();
        final JsonNode logo = admin.upload(assets, Map.of(), "logo.svg", "image/svg+xml",
                SVG.getBytes(StandardCharsets.UTF_8)).json();
        final String logoUrl = logo.path("url").asText();
        final String orgName = E2eSeed.unique("harbor");
        final String orgId = admin.post("/admin/realms/" + realm + "/organizations", Map.of("name", orgName))
                .json().path("orgId").asText();
        assertThat(admin.put("/admin/realms/" + realm + "/theme", Map.of(
                "typography", Map.of("fontSans", "Public Sans"),
                "assets", Map.of("logoUrl", logoUrl),
                "customCss", ".helix-brand { background-image: url(" + logoUrl + ") }")).status()).isEqualTo(200);
        assertThat(admin.put("/admin/realms/" + realm + "/organizations/" + orgId + "/theme",
                Map.of("assets", Map.of("faviconUrl", logoUrl))).status()).isEqualTo(200);

        final E2eHttp.BytesResponse export = admin.getBytes("/admin/realms/" + realm + "/export?includeAssets=true");
        assertThat(export.status()).isEqualTo(200);
        assertThat(export.header("Content-Type").orElseThrow()).startsWith("application/zip");
        assertThat(export.header("Content-Disposition").orElseThrow()).startsWith("attachment");
        final Map<String, byte[]> entries = unzip(export.body());
        assertThat(entries).containsKeys("realm-export.json", "theme-assets/manifest.json",
                "theme-assets/" + font.path("id").asText() + ".woff2", "theme-assets/" + logo.path("id").asText() + ".svg");
        final JsonNode manifest = JSON.readTree(entries.get("theme-assets/manifest.json"));
        assertThat(manifest).hasSize(2);
        assertThat(manifest.findValuesAsText("sha256")).contains(font.path("sha256").asText(), logo.path("sha256").asText());
        assertThat(manifest.findValuesAsText("name")).contains("Public Sans");

        // Into a different realm: assets get new ids there, and every reference follows.
        final String target = E2eSeed.unique("copy");
        seed().realm(target);
        final E2eAdminSession master = adminSession();
        final E2eHttp.Response imported = master.postBytes("/admin/realms/" + target + "/import", "application/zip",
                export.body());
        assertThat(imported.status()).as(imported.toString()).isEqualTo(200);
        assertThat(imported.json().path("slices").path("themeAssets").path("created").asInt()).isEqualTo(2);

        final JsonNode copied = master.get("/admin/realms/" + target + "/theme/assets").json();
        assertThat(copied).hasSize(2);
        final String newLogo = copied.findValuesAsText("url").stream().filter(u -> u.endsWith(".svg")).findFirst().orElseThrow();
        assertThat(newLogo).startsWith("/realms/" + target + "/theme/assets/").doesNotContain(logo.path("id").asText());

        final JsonNode theme = master.get("/admin/realms/" + target + "/theme").json();
        assertThat(theme.path("typography").path("fontSans").asText()).isEqualTo("Public Sans");
        assertThat(theme.path("assets").path("logoUrl").asText()).isEqualTo(newLogo);
        assertThat(theme.path("customCss").asText()).isEqualTo(".helix-brand { background-image: url(" + newLogo + ") }");
        final String copiedOrg = master.get("/admin/realms/" + target + "/organizations").json().findValues("orgId")
                .stream().map(JsonNode::asText).findFirst().orElseThrow();
        assertThat(master.get("/admin/realms/" + target + "/organizations/" + copiedOrg + "/theme").json()
                .path("assets").path("faviconUrl").asText()).isEqualTo(newLogo);
        assertThat(newBrowser().getBytes(newLogo).body()).isEqualTo(SVG.getBytes(StandardCharsets.UTF_8));

        // Importing the same archive again reuses the identical assets instead of failing on limits or duplicates.
        final E2eHttp.Response again = master.postBytes("/admin/realms/" + target + "/import", "application/zip",
                export.body());
        assertThat(again.status()).as(again.toString()).isEqualTo(200);
        assertThat(master.get("/admin/realms/" + target + "/theme/assets").json()).hasSize(2);

        // The plain JSON import keeps working as before.
        assertThat(admin.post("/admin/realms/" + realm + "/import",
                admin.get("/admin/realms/" + realm + "/export").json()).status()).isEqualTo(200);
    }

    @Test
    void aTamperedOrMaliciousArchiveIsRefused_andNothingIsImported() throws Exception {
        final JsonNode logo = admin.upload("/admin/realms/" + realm + "/theme/assets", Map.of(), "logo.svg",
                "image/svg+xml", SVG.getBytes(StandardCharsets.UTF_8)).json();
        final Map<String, byte[]> entries = unzip(admin.getBytes("/admin/realms/" + realm + "/export?includeAssets=true").body());
        final String file = "theme-assets/" + logo.path("id").asText() + ".svg";
        final String target = E2eSeed.unique("victim");
        seed().realm(target);
        final E2eAdminSession master = adminSession();
        final String importPath = "/admin/realms/" + target + "/import";

        // The bytes no longer match the manifest's sha256.
        final Map<String, byte[]> tampered = new LinkedHashMap<>(entries);
        tampered.put(file, SVG.replace("#1f4d47", "#000000").getBytes(StandardCharsets.UTF_8));
        final E2eHttp.Response badSha = master.postBytes(importPath, "application/zip", zip(tampered));
        assertThat(badSha.status()).as(badSha.toString()).isEqualTo(400);
        assertThat(badSha.json().path("message").asText()).contains("sha256");

        // A malicious SVG with a matching manifest still goes through the upload rules.
        final byte[] evil = SVG.replace("<rect", "<script>alert(1)</script><rect").getBytes(StandardCharsets.UTF_8);
        final Map<String, byte[]> malicious = new LinkedHashMap<>(entries);
        malicious.put(file, evil);
        final ArrayNode manifest = (ArrayNode) JSON.readTree(entries.get("theme-assets/manifest.json"));
        ((ObjectNode) manifest.get(0)).put("sha256", sha256(evil));
        malicious.put("theme-assets/manifest.json", JSON.writeValueAsBytes(manifest));
        final E2eHttp.Response refused = master.postBytes(importPath, "application/zip", zip(malicious));
        assertThat(refused.status()).as(refused.toString()).isEqualTo(422);
        assertThat(refused.body()).contains("script");

        // Zip-slip names and files missing from the manifest are refused before anything is imported.
        final Map<String, byte[]> slip = new LinkedHashMap<>(entries);
        slip.put("../../etc/cron.d/x", new byte[] {1});
        assertThat(master.postBytes(importPath, "application/zip", zip(slip)).status()).isEqualTo(400);
        final Map<String, byte[]> extra = new LinkedHashMap<>(entries);
        extra.put("theme-assets/stray.png", AssetFixtures.png());
        assertThat(master.postBytes(importPath, "application/zip", zip(extra)).status()).isEqualTo(400);
        assertThat(master.postBytes(importPath, "application/zip", "not a zip".getBytes(StandardCharsets.UTF_8)).status())
                .isEqualTo(400);

        assertThat(master.get("/admin/realms/" + target + "/theme/assets").json()).isEmpty();
    }

    private static String sha256(final byte[] b) throws Exception {
        return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(b));
    }
}
