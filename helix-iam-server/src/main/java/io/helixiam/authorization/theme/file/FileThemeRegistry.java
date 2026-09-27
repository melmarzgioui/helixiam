/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.file;

import io.helixiam.authorization.theme.BaseThemeProvider;
import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeService;
import io.helixiam.authorization.theme.asset.MountedThemeAssets;
import io.helixiam.authorization.theme.asset.ThemeAssetMetadata;
import io.helixiam.authorization.theme.asset.ThemeAssetService;
import io.helixiam.common.log.LogSafe;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * File themes (structured theming spec §5): the themes under {@code helix.theme.directory}, validated at startup and
 * on every reload, and the base layer of each realm that selected one ({@code realm_theme.theme_name}).
 *
 * <ul>
 *   <li>A theme that fails validation is refused: it is logged with every problem, and a realm that selected it falls
 *       back to its database theme or the default (it never keeps an older copy of the files).</li>
 *   <li>The directory is polled every {@code helix.theme.reload-interval-seconds} (default 30, 0 = only at
 *       startup); when anything under it changes, every theme is reloaded and the effective-theme cache is dropped
 *       ({@link ThemeService#invalidateAll()}). A Kubernetes ConfigMap update swaps the files atomically, which the
 *       poll picks up.</li>
 *   <li>The layer sits between the HelixIAM default and the realm's database layer, so database fields override the
 *       file's values.</li>
 *   <li>The theme's files are served under the selecting realm's asset path, through {@link MountedThemeAssets}.</li>
 * </ul>
 */
@Component
@Order(0)
public class FileThemeRegistry implements BaseThemeProvider, MountedThemeAssets {

    private static final Logger LOG = LogManager.getLogger(FileThemeRegistry.class);

    public static final String DIRECTORY = "helix.theme.directory";
    public static final String RELOAD_INTERVAL = "helix.theme.reload-interval-seconds";

    private final ThemeService themes;
    private final Path directory;
    private final Set<String> operatorOrigins;
    private final long reloadSeconds;
    private final Set<String> warned = ConcurrentHashMap.newKeySet();
    private volatile Map<String, FileThemeLoader.Result> results = Map.of();
    private volatile String scanFingerprint = "";
    private volatile Instant loadedAt = Instant.EPOCH;
    private ScheduledExecutorService poller;

    @Autowired
    public FileThemeRegistry(final ThemeService themes,
                             @Value("${" + DIRECTORY + ":}") final String directory,
                             @Value("${" + RELOAD_INTERVAL + ":30}") final long reloadSeconds,
                             @Value("${" + ThemeService.ALLOWED_IMAGE_ORIGINS + ":}") final String allowedImageOrigins) {
        this.themes = themes;
        this.directory = directory == null || directory.isBlank() ? null : Path.of(directory.trim());
        this.reloadSeconds = reloadSeconds;
        this.operatorOrigins = ThemeService.parseOrigins(allowedImageOrigins);
    }

    /** Loads the themes at startup (validation happens here) and starts the change poll. */
    @PostConstruct
    public void start() {
        if (directory == null) {
            return;
        }
        reload();
        if (reloadSeconds > 0) {
            poller = Executors.newSingleThreadScheduledExecutor(r -> {
                final Thread t = new Thread(r, "helix-file-theme-reload");
                t.setDaemon(true);
                return t;
            });
            poller.scheduleWithFixedDelay(this::reloadIfChanged, reloadSeconds, reloadSeconds, TimeUnit.SECONDS);
        }
    }

    @PreDestroy
    public void stop() {
        if (poller != null) {
            poller.shutdownNow();
        }
    }

    /** True when {@code helix.theme.directory} is set. */
    public boolean enabled() {
        return directory != null;
    }

    /** Every theme found at the last (re)load, valid or refused, by name. */
    public Map<String, FileThemeLoader.Result> results() {
        return results;
    }

    /** The last load of one theme. */
    public Optional<FileThemeLoader.Result> result(final String name) {
        return Optional.ofNullable(name == null ? null : results.get(name));
    }

    /**
     * Reloads every theme from the directory, logs the outcome of each, and drops the cached effective themes.
     * A directory that cannot be read leaves no themes (every realm falls back).
     */
    public synchronized Map<String, FileThemeLoader.Result> reload() {
        if (directory == null) {
            return Map.of();
        }
        scanFingerprint = scan();
        final Map<String, FileThemeLoader.Result> fresh = new LinkedHashMap<>();
        try {
            for (final String name : FileThemeLoader.names(directory)) {
                fresh.put(name, FileThemeLoader.load(directory, name, operatorOrigins));
            }
        } catch (final IOException | RuntimeException e) {
            LOG.error("File themes: {} ({}) cannot be read; no file theme is used: {}", DIRECTORY,
                    LogSafe.sanitize(directory.toString()), LogSafe.sanitize(e.getMessage()));
        }
        for (final FileThemeLoader.Result r : fresh.values()) {
            final FileThemeLoader.Result before = results.get(r.name());
            if (r.valid()) {
                if (before == null || !before.valid()
                        || !before.theme().fingerprint().equals(r.theme().fingerprint())) {
                    LOG.info("File theme {} loaded ({} assets).", LogSafe.sanitize(r.name()), r.theme().assets().size());
                }
            } else {
                LOG.error("File theme {} is refused and not used; realms that select it use their database theme or "
                                + "the default. Problems: {}", LogSafe.sanitize(r.name()),
                        LogSafe.sanitize(describe(r.problems())));
            }
        }
        results.keySet().stream().filter(n -> !fresh.containsKey(n))
                .forEach(n -> LOG.warn("File theme {} was removed from {}.", LogSafe.sanitize(n), DIRECTORY));
        results = Map.copyOf(fresh);
        loadedAt = Instant.now();
        warned.clear();
        themes.invalidateAll();
        return results;
    }

    /** The poll: reloads only when a file under the directory changed (name, size or modification time). */
    void reloadIfChanged() {
        try {
            if (!scan().equals(scanFingerprint)) {
                reload();
            }
        } catch (final RuntimeException e) {
            LOG.warn("File theme reload failed: {}", LogSafe.sanitize(e.getMessage()));
        }
    }

    private String scan() {
        try (Stream<Path> files = Files.walk(directory, 4, FileVisitOption.FOLLOW_LINKS)) {
            final String listing = files.sorted().map(p -> {
                try {
                    return p + "|" + Files.size(p) + "|" + Files.getLastModifiedTime(p).toMillis();
                } catch (final IOException e) {
                    return p + "|?";
                }
            }).collect(Collectors.joining("\n"));
            return FileThemeLoader.sha256(listing.getBytes(StandardCharsets.UTF_8));
        } catch (final IOException | RuntimeException e) {
            return "unreadable:" + e.getClass().getSimpleName();
        }
    }

    // ------------------------------------------------------------------ BaseThemeProvider

    @Override
    public Optional<Theme> baseTheme(final String realmId) {
        return selected(realmId).map(t -> t.forRealm(realmId));
    }

    /** The valid file theme {@code realmId} selected; empty (logged once per reload) when it is missing or refused. */
    Optional<FileTheme> selected(final String realmId) {
        if (directory == null || realmId == null) {
            return Optional.empty();
        }
        final Optional<String> name = themes.themeName(realmId);
        if (name.isEmpty()) {
            return Optional.empty();
        }
        final FileThemeLoader.Result r = results.get(name.get());
        if (r != null && r.valid()) {
            return Optional.of(r.theme());
        }
        if (warned.add(realmId + "|" + name.get())) {
            LOG.warn("Realm {} selects file theme {}, which is {}; it uses its database theme or the default.",
                    LogSafe.sanitize(realmId), LogSafe.sanitize(name.get()), r == null ? "not in " + DIRECTORY
                            : "refused (see the error logged when it was loaded)");
        }
        return Optional.empty();
    }

    // ------------------------------------------------------------------ MountedThemeAssets

    @Override
    public Optional<ThemeAssetService.StoredAsset> find(final String realmId, final String assetId) {
        if (assetId == null || !assetId.startsWith("ft-")) {
            return Optional.empty(); // uploaded ids never start with ft-; skip the lookup for them
        }
        final Instant at = loadedAt;
        return selected(realmId).flatMap(t -> t.asset(assetId))
                .map(a -> new ThemeAssetService.StoredAsset(a.metadata(realmId, at), a.bytes()));
    }

    @Override
    public List<ThemeAssetMetadata> fonts(final String realmId) {
        final Instant at = loadedAt;
        return selected(realmId).map(t -> t.fonts().stream().map(a -> a.metadata(realmId, at)).toList())
                .orElse(List.of());
    }

    static String describe(final Map<String, String> problems) {
        return problems.entrySet().stream().map(e -> e.getKey() + ": " + e.getValue())
                .collect(Collectors.joining("; "));
    }
}
