/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.theme.EffectiveTheme;
import io.helixiam.authorization.theme.Theme;
import io.helixiam.authorization.theme.ThemeService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Structured theming admin API (spec §7). The realm theme needs {@code manage-realm}; an organization theme needs
 * {@code manage-organizations} ({@code AdminRoutePermissions}). {@code PUT} replaces the stored layer and answers
 * {@code 400 {message, fieldErrors}} when it is not valid (field keys are JSON paths such as
 * {@code colors.primary.light} or {@code contrast.inkOnSurface.dark}). {@code GET} returns the stored layer, or with
 * {@code ?effective=true} the merged result (organization → realm → default, dark values derived) plus its
 * {@code version}. Organizations are looked up inside the path realm only (another realm's organization is a 404).
 * Changes are audited with the names of the fields changed.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}")
@Tag(name = "Theme", description = "Structured realm and organization theming")
public class ThemeAdminController {

    private final ThemeService themes;

    public ThemeAdminController(final ThemeService themes) {
        this.themes = themes;
    }

    @GetMapping("/theme")
    @Operation(summary = "The realm's theme layer, or with effective=true the resolved theme")
    public ResponseEntity<ThemeView> getRealmTheme(@PathVariable final String realmId,
                                                   @RequestParam(name = "effective", defaultValue = "false")
                                                   final boolean effective) {
        if (!themes.realmExists(realmId)) {
            return ResponseEntity.notFound().build();
        }
        if (effective) {
            return ResponseEntity.ok(effectiveView(themes.effectiveTheme(realmId, Optional.empty())));
        }
        final Theme stored = themes.realmTheme(realmId);
        return ResponseEntity.ok(new ThemeView(stored, themes.notices(stored), null));
    }

    @PutMapping("/theme")
    @Operation(summary = "Replace the realm's theme layer (validated)")
    public ResponseEntity<ThemeView> putRealmTheme(@PathVariable final String realmId,
                                                   @RequestBody final Theme theme,
                                                   final HttpServletRequest request) {
        if (!themes.realmExists(realmId)) {
            return ResponseEntity.notFound().build();
        }
        final ThemeService.ThemeChange change = themes.saveRealmTheme(realmId, theme);
        audit(request, change);
        return ResponseEntity.ok(new ThemeView(change.theme(), themes.notices(change.theme()), null));
    }

    @GetMapping("/organizations/{orgId}/theme")
    @Operation(summary = "An organization's theme layer, or with effective=true the resolved theme")
    public ResponseEntity<ThemeView> getOrganizationTheme(@PathVariable final String realmId,
                                                          @PathVariable final String orgId,
                                                          @RequestParam(name = "effective", defaultValue = "false")
                                                          final boolean effective) {
        final Optional<Theme> stored = themes.organizationTheme(realmId, orgId);
        if (stored.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        if (effective) {
            return ResponseEntity.ok(effectiveView(themes.effectiveTheme(realmId, Optional.of(orgId))));
        }
        return ResponseEntity.ok(new ThemeView(stored.get(), themes.notices(stored.get()), null));
    }

    @PutMapping("/organizations/{orgId}/theme")
    @Operation(summary = "Replace an organization's theme layer (validated; no custom CSS)")
    public ResponseEntity<ThemeView> putOrganizationTheme(@PathVariable final String realmId,
                                                          @PathVariable final String orgId,
                                                          @RequestBody final Theme theme,
                                                          final HttpServletRequest request) {
        return themes.saveOrganizationTheme(realmId, orgId, theme)
                .map(change -> {
                    audit(request, change);
                    return ResponseEntity.ok(new ThemeView(change.theme(), themes.notices(change.theme()), null));
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    private ThemeView effectiveView(final EffectiveTheme e) {
        return new ThemeView(e.theme(), themes.notices(e.theme()), e.version());
    }

    private static void audit(final HttpServletRequest request, final ThemeService.ThemeChange change) {
        if (!change.changedFields().isEmpty()) {
            AuditContext.attachDetail(request, Map.of("fieldsChanged", String.join(",", change.changedFields())));
        }
    }

    /** A theme plus read-only admin notices (and, for the effective theme, its version). */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public record ThemeView(@JsonUnwrapped Theme theme, List<String> notices, String version) {
    }
}
