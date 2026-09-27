/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import io.helixiam.authorization.domain.org.Organization;
import io.helixiam.authorization.domain.theme.OrganizationThemeRecord;
import io.helixiam.authorization.domain.theme.RealmThemeRecord;
import io.helixiam.authorization.repository.org.OrganizationRepository;
import io.helixiam.authorization.repository.theme.OrganizationThemeRepository;
import io.helixiam.authorization.repository.theme.RealmThemeRepository;
import io.helixiam.authorization.service.RealmService;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Structured theming (spec §1, §7): stores and validates the realm and organization theme layers and resolves the
 * effective theme. This is the API later tasks build on:
 *
 * <ul>
 *   <li>{@link #effectiveTheme(String, Optional)} — merged organization → realm → base layers → default, dark
 *       values derived, stored custom CSS re-validated (dropped with a warning when it no longer validates), plus a
 *       stable {@link EffectiveTheme#version()} for ETags, the realm's {@code img-src} origins and the (operator-only)
 *       custom-CSS url() allowlist. The organization id is resolved to an organization of the realm before it is
 *       used as a cache key (unknown ids share the realm's entry); the cache is bounded, entries live 30 s and are
 *       invalidated after the commit of a local write.</li>
 *   <li>{@link #realmTheme}/{@link #organizationTheme} — the stored layers as saved (for the admin API/export).</li>
 *   <li>{@link #saveRealmTheme}/{@link #saveOrganizationTheme} — validate ({@link ThemeValidator}), normalise
 *       and store; throw {@link ThemeValidationException} with field errors.</li>
 *   <li>{@link #legacyBranding}/{@link #applyLegacyBranding} — the deprecated realm-settings branding fields.</li>
 * </ul>
 *
 * Uploaded fonts/assets are resolved through an optional {@link ThemeAssetCatalog} bean (Task 2) and base layers
 * through {@link BaseThemeProvider} beans (Task 5). Organization lookups are always scoped to the realm: an
 * organization of another realm behaves as if it does not exist.
 */
@Service
public class ThemeService {

    private static final Logger LOG = LogManager.getLogger(ThemeService.class);

    /** Comma-separated https origins images (and custom-CSS {@code url()}) may load from, for every realm. */
    public static final String ALLOWED_IMAGE_ORIGINS = "helix.theme.allowed-image-origins";

    private static final long CACHE_TTL_MILLIS = 30_000L;

    private final RealmThemeRepository realmThemes;
    private final OrganizationThemeRepository organizationThemes;
    private final OrganizationRepository organizations;
    private final RealmService realms;
    private final ObjectProvider<ThemeAssetCatalog> catalog;
    private final ObjectProvider<BaseThemeProvider> baseProviders;
    private final Set<String> allowedImageOrigins;
    private final LongSupplier clock = System::currentTimeMillis;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();
    private int maxCacheEntries = 10_000;

    @Autowired
    public ThemeService(final RealmThemeRepository realmThemes,
                        final OrganizationThemeRepository organizationThemes,
                        final OrganizationRepository organizations,
                        final RealmService realms,
                        final ObjectProvider<ThemeAssetCatalog> catalog,
                        final ObjectProvider<BaseThemeProvider> baseProviders,
                        @Value("${" + ALLOWED_IMAGE_ORIGINS + ":}") final String allowedImageOrigins) {
        this.realmThemes = realmThemes;
        this.organizationThemes = organizationThemes;
        this.organizations = organizations;
        this.realms = realms;
        this.catalog = catalog;
        this.baseProviders = baseProviders;
        this.allowedImageOrigins = parseOrigins(allowedImageOrigins);
    }

    /** Parses the configured origin allowlist (invalid entries are ignored with a warning). */
    public static Set<String> parseOrigins(final String csv) {
        final Set<String> out = new LinkedHashSet<>();
        if (csv == null || csv.isBlank()) {
            return out;
        }
        for (final String raw : csv.split(",")) {
            if (raw.isBlank()) {
                continue;
            }
            final String origin = ThemeUrls.normalizeOrigin(raw);
            if (origin == null) {
                LOG.warn("Ignoring {} entry that is not an https origin: {}", ALLOWED_IMAGE_ORIGINS, LogSafe.sanitize(raw));
            } else {
                out.add(origin);
            }
        }
        return out;
    }

    /** A saved layer and the JSON paths of the fields that changed (for audit; never values). */
    public record ThemeChange(Theme theme, List<String> changedFields) {
    }

    // ---------------------------------------------------------------- reads

    public boolean realmExists(final String realmId) {
        return realmId != null && realms.exists(realmId);
    }

    /** The realm's stored layer; {@link Theme#EMPTY} when none. */
    @Transactional(readOnly = true)
    public Theme realmTheme(final String realmId) {
        return realmThemes.findById(realmId).map(r -> read(r.getThemeJson(), "realm " + realmId)).orElse(Theme.EMPTY);
    }

    /** The organization's stored layer ({@link Theme#EMPTY} when none); empty when the organization is not in the realm. */
    @Transactional(readOnly = true)
    public Optional<Theme> organizationTheme(final String realmId, final String orgId) {
        return organizationInRealm(realmId, orgId).map(o -> storedOrganizationTheme(o.getOrgId()));
    }

    /** Every organization layer of the realm that sets something, keyed by organization id. */
    @Transactional(readOnly = true)
    public Map<String, Theme> organizationThemes(final String realmId) {
        final Map<String, Theme> out = new LinkedHashMap<>();
        for (final OrganizationThemeRecord r : organizationThemes.findAllByRealmId(realmId)) {
            final Theme t = read(r.getThemeJson(), "organization " + r.getOrgId());
            if (!t.isEmpty()) {
                out.put(r.getOrgId(), t);
            }
        }
        return out;
    }

    /**
     * The effective theme: organization (when {@code orgId} is present and belongs to the realm) → realm → base
     * layers → HelixIAM default, merged field by field, dark values derived.
     */
    public EffectiveTheme effectiveTheme(final String realmId, final Optional<String> orgId) {
        // Review I2: a caller-supplied org id (e.g. a public ?org= hint) is resolved to an organization of the realm
        // BEFORE it becomes a cache key; anything else shares the realm's key.
        final Optional<String> org = orgId.flatMap(id -> organizationInRealm(realmId, id)).map(Organization::getOrgId);
        final String key = realmId + "|" + org.orElse("");
        final Cached hit = cache.get(key);
        if (hit != null && clock.getAsLong() - hit.at() < CACHE_TTL_MILLIS) {
            return hit.value();
        }
        final EffectiveTheme fresh = computeEffective(realmId, org);
        if (cache.size() >= maxCacheEntries) {
            cache.clear(); // bounded: a burst of distinct realms/orgs can never grow the heap without limit
        }
        cache.put(key, new Cached(fresh, clock.getAsLong()));
        return fresh;
    }

    private EffectiveTheme computeEffective(final String realmId, final Optional<String> resolvedOrgId) {
        final List<Theme> layers = new ArrayList<>(belowRealm(realmId));
        layers.add(realmTheme(realmId));
        resolvedOrgId.ifPresent(id -> layers.add(storedOrganizationTheme(id)));
        Theme merged = DarkPalette.resolve(ThemeMerger.merge(layers));
        merged = merged.withCustomCss(servableCss(realmId, merged.customCss()));
        final ThemeValidator validator = validator();
        return new EffectiveTheme(merged, ThemeJson.hash(merged), validator.imageOrigins(merged),
                validator.cssUrlOrigins());
    }

    /**
     * {@code css} when it passes the CURRENT custom-CSS rules (operator allowlist, uploaded assets), else null with a
     * warning (spec §4: stored CSS that no longer validates is logged and skipped).
     */
    private String servableCss(final String realmId, final String css) {
        if (css == null) {
            return null;
        }
        final List<String> problems = CustomCssValidator.problems(css, realmId, allowedImageOrigins,
                catalog.getIfAvailable(() -> ThemeAssetCatalog.NONE));
        if (problems.isEmpty()) {
            return css;
        }
        LOG.warn("Realm {}: stored custom CSS no longer validates and is not served: {}",
                LogSafe.sanitize(realmId), LogSafe.sanitize(problems.get(0)));
        return null;
    }

    /** The https origins images may load from for this realm (and organization), for the per-realm CSP. */
    public Set<String> allowedImageOrigins(final String realmId, final Optional<String> orgId) {
        return effectiveTheme(realmId, orgId).imageOrigins();
    }

    /** Admin-API notices for a stored layer (spec §4: custom CSS depends on internal markup). */
    public List<String> notices(final Theme theme) {
        return theme != null && theme.customCss() != null ? List.of(CustomCssValidator.NOTICE) : List.of();
    }

    // ---------------------------------------------------------------- writes

    /** Validates and stores the realm's layer (replacing it). */
    @Transactional
    public ThemeChange saveRealmTheme(final String realmId, final Theme theme) {
        final Theme candidate = ThemeNormalizer.normalize(theme);
        final Map<String, String> errors = validator().validate(realmId, ThemeValidator.Scope.REALM, candidate,
                ThemeMerger.merge(belowRealm(realmId)));
        if (!errors.isEmpty()) {
            throw new ThemeValidationException(errors);
        }
        return storeRealm(realmId, candidate);
    }

    /** Validates and stores an organization's layer; empty when the organization is not in the realm. */
    @Transactional
    public Optional<ThemeChange> saveOrganizationTheme(final String realmId, final String orgId, final Theme theme) {
        final Optional<Organization> org = organizationInRealm(realmId, orgId);
        if (org.isEmpty()) {
            return Optional.empty();
        }
        final Theme candidate = ThemeNormalizer.normalize(theme);
        final Map<String, String> errors = validator().validate(realmId, ThemeValidator.Scope.ORGANIZATION, candidate,
                belowOrganization(realmId));
        if (!errors.isEmpty()) {
            throw new ThemeValidationException(errors);
        }
        return Optional.of(storeOrganization(realmId, org.get().getOrgId(), candidate));
    }

    /**
     * Applies a partial change to an organization's layer (used by the 1.0 organization-branding API): only what
     * the patch introduces is validated. Error keys are translated through {@code errorKeys} (path prefix →
     * caller's field name). Empty when the organization is not in the realm.
     */
    @Transactional
    public Optional<ThemeChange> patchOrganizationTheme(final String realmId, final String orgId,
                                                        final java.util.function.UnaryOperator<Theme> patch,
                                                        final Map<String, String> errorKeys) {
        final Optional<Organization> org = organizationInRealm(realmId, orgId);
        if (org.isEmpty()) {
            return Optional.empty();
        }
        final Theme stored = storedOrganizationTheme(org.get().getOrgId());
        final Theme patched = ThemeNormalizer.normalize(patch.apply(stored));
        final Theme delta = ThemeDiff.delta(stored, patched);
        final Map<String, String> errors = validator().validate(realmId, ThemeValidator.Scope.ORGANIZATION, delta,
                ThemeMerger.merge(belowOrganization(realmId), stored));
        if (!errors.isEmpty()) {
            throw new ThemeValidationException(translate(errors, errorKeys));
        }
        return Optional.of(storeOrganization(realmId, org.get().getOrgId(), patched));
    }

    /**
     * The deprecated realm-settings branding fields, read from the realm's layer, for serving: {@code customCss} is
     * present only when it passes the current rules (review C1: nothing unvalidated reaches a page).
     */
    @Transactional(readOnly = true)
    public LegacyBranding legacyBranding(final String realmId) {
        final LegacyBranding stored = storedLegacyBranding(realmId);
        return new LegacyBranding(stored.logoUrl(), stored.primaryColor(), stored.backgroundColor(),
                stored.welcomeText(), servableCss(realmId, stored.customCss()));
    }

    /** The legacy fields exactly as stored (used to leave them untouched, e.g. by import). */
    @Transactional(readOnly = true)
    public LegacyBranding storedLegacyBranding(final String realmId) {
        return LegacyBranding.of(realmTheme(realmId));
    }

    /** Legacy field → theme path prefixes whose errors it reports. */
    public static final Map<String, String> LEGACY_ERROR_KEYS = legacyKeys();

    private static Map<String, String> legacyKeys() {
        final Map<String, String> m = new LinkedHashMap<>();
        m.put("assets.logoUrl", "logoUrl");
        m.put("colors.primary", "primaryColor");
        m.put("contrast.textOnPrimary", "primaryColor");
        m.put("colors.surface", "backgroundColor");
        m.put("contrast.inkOnSurface", "backgroundColor");
        m.put("texts.welcomeText", "welcomeText");
        m.put("customCss", "customCss");
        return m;
    }

    /**
     * Writes the deprecated realm-settings branding fields onto the realm's layer, keeping everything else. A no-op
     * when they are unchanged; otherwise only what changed is validated, and errors are reported under the legacy
     * field names ({@code logoUrl}, {@code primaryColor}, {@code backgroundColor}, {@code welcomeText},
     * {@code customCss}).
     */
    @Transactional
    public void applyLegacyBranding(final String realmId, final LegacyBranding legacy) {
        final LegacyBranding incoming = legacy == null ? LegacyBranding.NONE : legacy.normalized();
        final Theme stored = realmTheme(realmId);
        if (incoming.equals(LegacyBranding.of(stored))) {
            return;
        }
        final Theme patched = ThemeNormalizer.normalize(incoming.applyTo(stored));
        final Theme delta = ThemeDiff.delta(stored, patched);
        final Map<String, String> errors = validator().validate(realmId, ThemeValidator.Scope.REALM, delta,
                ThemeMerger.merge(ThemeMerger.merge(belowRealm(realmId)), stored));
        if (!errors.isEmpty()) {
            throw new ThemeValidationException(translate(errors, LEGACY_ERROR_KEYS));
        }
        storeRealm(realmId, patched);
    }

    /** Checks a legacy branding change without storing it (same rules as {@link #applyLegacyBranding}). */
    @Transactional(readOnly = true)
    public Map<String, String> validateLegacyBranding(final String realmId, final LegacyBranding legacy) {
        final LegacyBranding incoming = legacy == null ? LegacyBranding.NONE : legacy.normalized();
        final Theme stored = realmTheme(realmId);
        if (incoming.equals(LegacyBranding.of(stored))) {
            return Map.of();
        }
        final Theme patched = ThemeNormalizer.normalize(incoming.applyTo(stored));
        return translate(validator().validate(realmId, ThemeValidator.Scope.REALM, ThemeDiff.delta(stored, patched),
                ThemeMerger.merge(ThemeMerger.merge(belowRealm(realmId)), stored)), LEGACY_ERROR_KEYS);
    }

    // ---------------------------------------------------------------- internals

    private ThemeChange storeRealm(final String realmId, final Theme candidate) {
        final Optional<RealmThemeRecord> row = realmThemes.findById(realmId);
        final Theme before = row.map(r -> read(r.getThemeJson(), "realm " + realmId)).orElse(Theme.EMPTY);
        final String json = ThemeJson.write(candidate);
        final RealmThemeRecord record = row.orElseGet(() -> new RealmThemeRecord(realmId, json));
        record.setThemeJson(json);
        realmThemes.save(record);
        invalidateAfterCommit(realmId);
        return new ThemeChange(candidate, ThemeDiff.changedFields(before, candidate));
    }

    private ThemeChange storeOrganization(final String realmId, final String orgId, final Theme candidate) {
        final Optional<OrganizationThemeRecord> row = organizationThemes.findById(orgId);
        final Theme before = row.map(r -> read(r.getThemeJson(), "organization " + orgId)).orElse(Theme.EMPTY);
        final String json = ThemeJson.write(candidate);
        final OrganizationThemeRecord record = row.orElseGet(() -> new OrganizationThemeRecord(orgId, realmId, json));
        record.setThemeJson(json);
        organizationThemes.save(record);
        invalidateAfterCommit(realmId);
        return new ThemeChange(candidate, ThemeDiff.changedFields(before, candidate));
    }

    private Theme storedOrganizationTheme(final String orgId) {
        return organizationThemes.findById(orgId).map(r -> read(r.getThemeJson(), "organization " + orgId))
                .orElse(Theme.EMPTY);
    }

    private Optional<Organization> organizationInRealm(final String realmId, final String orgId) {
        if (realmId == null || orgId == null) {
            return Optional.empty();
        }
        return organizations.findById(orgId).filter(o -> realmId.equals(o.getTenantId()));
    }

    /** Default + base layers (e.g. a file theme) for the realm. */
    private List<Theme> belowRealm(final String realmId) {
        final List<Theme> layers = new ArrayList<>();
        layers.add(ThemeDefaults.THEME);
        baseProviders.orderedStream().forEach(p -> {
            try {
                p.baseTheme(realmId).ifPresent(layers::add);
            } catch (final RuntimeException e) {
                LOG.warn("Base theme provider {} failed for realm {}: {}", p.getClass().getSimpleName(),
                        LogSafe.sanitize(realmId), LogSafe.sanitize(e.getMessage()));
            }
        });
        return layers;
    }

    private Theme belowOrganization(final String realmId) {
        final List<Theme> layers = new ArrayList<>(belowRealm(realmId));
        layers.add(realmTheme(realmId));
        return ThemeMerger.merge(layers);
    }

    private ThemeValidator validator() {
        return new ThemeValidator(catalog.getIfAvailable(() -> ThemeAssetCatalog.NONE), allowedImageOrigins);
    }

    /**
     * Review M2: drop the realm's cached effective themes only once the write is committed — invalidating inside
     * the transaction would let a concurrent read re-cache the pre-commit theme for the whole TTL.
     */
    private void invalidateAfterCommit(final String realmId) {
        if (org.springframework.transaction.support.TransactionSynchronizationManager.isSynchronizationActive()) {
            org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(
                    new org.springframework.transaction.support.TransactionSynchronization() {
                        @Override
                        public void afterCommit() {
                            invalidate(realmId);
                        }
                    });
        } else {
            invalidate(realmId);
        }
    }

    /** Test seam: the number of cached effective themes. */
    int cacheSize() {
        return cache.size();
    }

    /** Test seam: the cache bound. */
    void maxCacheEntries(final int max) {
        this.maxCacheEntries = max;
    }

    /** Drops the cached effective themes of a realm (done after every local write; for base-layer reloads). */
    public void invalidate(final String realmId) {
        cache.keySet().removeIf(k -> k.startsWith(realmId + "|"));
    }

    /** Drops every cached effective theme (e.g. after file themes were reloaded). */
    public void invalidateAll() {
        cache.clear();
    }

    private static Theme read(final String json, final String owner) {
        try {
            return ThemeJson.read(json);
        } catch (final IllegalArgumentException e) {
            LOG.warn("Stored theme of {} is unreadable and is ignored: {}", LogSafe.sanitize(owner),
                    LogSafe.sanitize(e.getMessage()));
            return Theme.EMPTY;
        }
    }

    /** Maps error keys by path prefix (first match wins); unmapped keys are kept. */
    static Map<String, String> translate(final Map<String, String> errors, final Map<String, String> keys) {
        final Map<String, String> out = new LinkedHashMap<>();
        errors.forEach((path, message) -> {
            final String mapped = keys.entrySet().stream()
                    .filter(e -> path.equals(e.getKey()) || path.startsWith(e.getKey() + "."))
                    .map(Map.Entry::getValue).findFirst().orElse(path);
            out.putIfAbsent(mapped, message);
        });
        return out;
    }

    private record Cached(EffectiveTheme value, long at) {
    }
}
