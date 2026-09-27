/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin.io;

import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeAssets;
import io.helixiam.authorization.theme.ThemeTypography;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Review I2: the realm archive (document + theme assets) is read defensively and asset references are rewritten. */
class RealmArchiveTest {

    private static final byte[] DOC = "{\"formatVersion\":2}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] MANIFEST = "[]".getBytes(StandardCharsets.UTF_8);

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

    /** ZipOutputStream refuses duplicate names: write two same-length names, then rename the second in place. */
    private static byte[] zipWithDuplicate(final String name) throws IOException {
        final String other = name.replace("a.png", "b.png");
        final Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put(RealmArchive.DOCUMENT, DOC);
        entries.put(name, new byte[] {1});
        entries.put(other, new byte[] {2});
        final String s = new String(zip(entries), StandardCharsets.ISO_8859_1).replace(other, name);
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static RealmArchive.Contents read(final byte[] zip) {
        return RealmArchive.read(new ByteArrayInputStream(zip), RealmArchive.Limits.DEFAULT);
    }

    @Test
    void aWrittenArchiveReadsBack() throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        RealmArchive.write(out, DOC, MANIFEST, Map.of("a1.png", new byte[] {1, 2, 3}));
        final RealmArchive.Contents c = read(out.toByteArray());
        assertThat(c.document()).isEqualTo(DOC);
        assertThat(c.manifest()).isEqualTo(MANIFEST);
        assertThat(c.assets()).containsOnlyKeys("a1.png");
        assertThat(c.assets().get("a1.png")).containsExactly(1, 2, 3);
    }

    @ParameterizedTest
    @ValueSource(strings = {"../evil.json", "/etc/passwd", "theme-assets/../../x.png", "theme-assets/sub/x.png",
            "theme-assets\\x.png", "theme-assets/x.exe", "theme-assets/x.png.html", "other.json", "C:/x.png",
            "theme-assets/.png", "theme-assets/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.png", "realm-export.json/"})
    void zipSlipAndUnexpectedNamesAreRefused(final String name) throws IOException {
        final Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put(RealmArchive.DOCUMENT, DOC);
        entries.put(name, new byte[] {1});
        assertThatThrownBy(() -> read(zip(entries))).isInstanceOf(RealmArchiveException.class)
                .hasMessageContaining("entry");
    }

    @Test
    void duplicateEntriesAreRefused() throws IOException {
        assertThatThrownBy(() -> read(zipWithDuplicate("theme-assets/a.png"))).isInstanceOf(RealmArchiveException.class)
                .hasMessageContaining("more than once");
    }

    @Test
    void theDocumentIsRequired_andGarbageIsRefused() throws IOException {
        assertThatThrownBy(() -> read(zip(Map.of(RealmArchive.MANIFEST, MANIFEST))))
                .isInstanceOf(RealmArchiveException.class).hasMessageContaining(RealmArchive.DOCUMENT);
        assertThatThrownBy(() -> read("not a zip".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(RealmArchiveException.class);
    }

    @Test
    void entryCountIsCapped() throws IOException {
        final Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put(RealmArchive.DOCUMENT, DOC);
        for (int i = 0; i < 5; i++) {
            entries.put("theme-assets/a" + i + ".png", new byte[] {1});
        }
        final RealmArchive.Limits small = new RealmArchive.Limits(5, 1024, 1024, 1024 * 1024, 1024 * 1024);
        assertThatThrownBy(() -> RealmArchive.read(new ByteArrayInputStream(zip(entries)), small))
                .isInstanceOf(RealmArchiveException.class).hasMessageContaining("entries");
    }

    @Test
    void zipBombs_areStoppedWhileReading() throws IOException {
        // 17 MB of zeros compresses to a few KB; the reader stops at the document cap without inflating it all.
        final byte[] bomb = zip(Map.of(RealmArchive.DOCUMENT, new byte[17 * 1024 * 1024]));
        assertThat(bomb.length).isLessThan(100_000);
        assertThatThrownBy(() -> read(bomb)).isInstanceOf(RealmArchiveException.class).hasMessageContaining("large");
        final byte[] bigAsset = zip(Map.of(RealmArchive.DOCUMENT, DOC, "theme-assets/a.png", new byte[600 * 1024]));
        assertThatThrownBy(() -> read(bigAsset)).isInstanceOf(RealmArchiveException.class).hasMessageContaining("large");
        // The total cap holds even when every single entry is within its own cap.
        final Map<String, byte[]> many = new LinkedHashMap<>();
        many.put(RealmArchive.DOCUMENT, DOC);
        for (int i = 0; i < 4; i++) {
            many.put("theme-assets/a" + i + ".png", new byte[1000]);
        }
        final RealmArchive.Limits total = new RealmArchive.Limits(64, 1000, 1000, 3000, 1024 * 1024);
        assertThatThrownBy(() -> RealmArchive.read(new ByteArrayInputStream(zip(many)), total))
                .isInstanceOf(RealmArchiveException.class).hasMessageContaining("large");
        final RealmArchive.Limits compressed = new RealmArchive.Limits(64, 1024 * 1024, 32 * 1024 * 1024,
                64 * 1024 * 1024, 100);
        assertThatThrownBy(() -> RealmArchive.read(new ByteArrayInputStream(bigAsset), compressed))
                .isInstanceOf(RealmArchiveException.class).hasMessageContaining("large");
    }

    @Test
    void assetReferencesAreRewrittenToTheTargetRealm() {
        final String logo = "/realms/src/theme/assets/old-1.svg";
        final Theme theme = new Theme(null, new ThemeTypography("Public Sans", null, null), null,
                new ThemeAssets(logo, "https://cdn.example/l.svg", logo, "/realms/src/theme/assets/unknown.png"),
                null, null, null, ".a{background:url(" + logo + ")} .b{background:url('/realms/src/theme/assets/old-1.svg')}");
        final Theme out = RealmArchive.rewrite(theme, "dst", Map.of("old-1", "new-9"));
        assertThat(out.assets().logoUrl()).isEqualTo("/realms/dst/theme/assets/new-9.svg");
        assertThat(out.assets().faviconUrl()).isEqualTo("/realms/dst/theme/assets/new-9.svg");
        assertThat(out.assets().logoDarkUrl()).isEqualTo("https://cdn.example/l.svg");
        assertThat(out.assets().brandImageUrl()).as("not in the archive: left for validation to refuse")
                .isEqualTo("/realms/src/theme/assets/unknown.png");
        assertThat(out.customCss()).isEqualTo(".a{background:url(/realms/dst/theme/assets/new-9.svg)} "
                + ".b{background:url('/realms/dst/theme/assets/new-9.svg')}");
        assertThat(out.typography().fontSans()).isEqualTo("Public Sans");
        assertThat(RealmArchive.rewrite(null, "dst", Map.of())).isNull();
        assertThat(List.of(RealmArchive.rewrite(Theme.EMPTY, "dst", Map.of("a", "b")))).containsExactly(Theme.EMPTY);
    }
}
