/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.file;

import io.helixiam.authorization.theme.ThemeService;
import io.helixiam.testsupport.LogCapture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** File themes (spec §5): startup load, change detection for reloads, and the per-realm base layer. */
class FileThemeRegistryTest {

    @TempDir
    Path root;

    private ThemeService themes;

    @BeforeEach
    void setUp() {
        themes = mock(ThemeService.class);
    }

    private FileThemeRegistry registry() {
        final FileThemeRegistry r = new FileThemeRegistry(themes, root.toString(), 0, "");
        r.start();
        return r;
    }

    private void write(final String name, final String json) throws IOException {
        final Path dir = Files.createDirectories(root.resolve(name));
        final Path file = dir.resolve("theme.json");
        Files.writeString(file, json);
        Files.setLastModifiedTime(file, FileTime.from(Instant.now().plusSeconds(Files.exists(file) ? 5 : 0)));
    }

    @Test
    void loadsAtStartup_andGivesTheSelectingRealmItsLayer() throws IOException {
        write("brand", "{\"shape\": {\"radius\": 6}}");
        final FileThemeRegistry registry = registry();
        when(themes.themeName("firm")).thenReturn(Optional.of("brand"));
        when(themes.themeName("plain")).thenReturn(Optional.empty());

        assertThat(registry.baseTheme("firm")).get().satisfies(t -> assertThat(t.shape().radius()).isEqualTo(6));
        assertThat(registry.baseTheme("plain")).isEmpty();
        verify(themes).invalidateAll();
    }

    @Test
    void reloadsOnlyWhenAFileChanged_andDropsTheCache() throws IOException {
        write("brand", "{\"shape\": {\"radius\": 6}}");
        final FileThemeRegistry registry = registry();
        registry.reloadIfChanged();
        verify(themes, times(1)).invalidateAll();

        write("brand", "{\"shape\": {\"radius\": 12}}");
        registry.reloadIfChanged();
        verify(themes, times(2)).invalidateAll();
        when(themes.themeName("firm")).thenReturn(Optional.of("brand"));
        assertThat(registry.baseTheme("firm")).get().satisfies(t -> assertThat(t.shape().radius()).isEqualTo(12));
    }

    @Test
    void aRefusedOrMissingThemeGivesNoLayer_andWarnsOncePerReload() throws IOException {
        write("broken", "{\"shape\": {\"radius\": 99}}");
        final FileThemeRegistry registry;
        try (LogCapture log = LogCapture.of(FileThemeRegistry.class)) {
            registry = registry();
            assertThat(log.text()).contains("File theme broken is refused", "shape.radius");
        }
        when(themes.themeName("firm")).thenReturn(Optional.of("broken"));
        when(themes.themeName("gone")).thenReturn(Optional.of("not-mounted"));
        try (LogCapture log = LogCapture.of(FileThemeRegistry.class)) {
            assertThat(registry.baseTheme("firm")).isEmpty();
            assertThat(registry.baseTheme("firm")).isEmpty();
            assertThat(registry.baseTheme("gone")).isEmpty();
            assertThat(log.messages()).filteredOn(m -> m.contains("Realm firm selects file theme broken")).hasSize(1);
            assertThat(log.text()).contains("Realm gone selects file theme not-mounted, which is not in");
        }
    }

    @Test
    void withoutADirectory_nothingIsLoaded() {
        final FileThemeRegistry r = new FileThemeRegistry(themes, "", 30, "");
        r.start();
        assertThat(r.enabled()).isFalse();
        assertThat(r.results()).isEmpty();
        assertThat(r.baseTheme("firm")).isEmpty();
        r.stop();
    }
}
