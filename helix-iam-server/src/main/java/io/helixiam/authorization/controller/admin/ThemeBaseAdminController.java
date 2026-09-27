/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.theme.ThemeService;
import io.helixiam.authorization.theme.ThemeValidationException;
import io.helixiam.authorization.theme.file.FileThemeLoader;
import io.helixiam.authorization.theme.file.FileThemeRegistry;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * File themes (structured theming spec §5): which file theme from {@code helix.theme.directory} a realm uses as its
 * base layer. Database theme fields ({@code PUT /admin/realms/{r}/theme}) override the file's values. Needs
 * {@code manage-realm} (the {@code theme} route group); audited as {@code THEME_UPDATE} with
 * {@code fieldsChanged=themeName}.
 *
 * <p>{@code PUT {"themeName": "monthfold"}} selects a theme that is loaded and valid; {@code {"themeName": null}}
 * clears it. A name that is not mounted, or a theme that was refused, is a {@code 400} with
 * {@code fieldErrors.themeName}. {@code GET} shows the selection, whether it is in use, and the themes available.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/theme/base")
@Tag(name = "Theme", description = "Structured realm and organization theming")
public class ThemeBaseAdminController {

    private final ThemeService themes;
    private final FileThemeRegistry files;

    public ThemeBaseAdminController(final ThemeService themes, final FileThemeRegistry files) {
        this.themes = themes;
        this.files = files;
    }

    /** One mounted theme: its name, whether it passed validation, and its problems when it did not. */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public record Available(String name, boolean valid, Map<String, String> problems) {
    }

    /**
     * The realm's file theme selection.
     *
     * @param themeName the selected theme, or null
     * @param status    {@code none} (no selection), {@code active} (in use), {@code refused} (it failed validation;
     *                  the realm uses its database theme or the default) or {@code missing} (not mounted)
     * @param directory whether {@code helix.theme.directory} is configured on this instance
     * @param available every theme found in the directory
     */
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record Selection(String themeName, String status, boolean directory, List<Available> available) {
    }

    @GetMapping
    @Operation(summary = "The file theme the realm uses as its base layer, and the themes available")
    public ResponseEntity<Selection> get(@PathVariable final String realmId) {
        if (!themes.realmExists(realmId)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(view(themes.themeName(realmId).orElse(null)));
    }

    @PutMapping
    @Operation(summary = "Select (or with null clear) the realm's file theme")
    public ResponseEntity<Selection> put(@PathVariable final String realmId, @RequestBody final JsonNode body,
                                         final HttpServletRequest request) {
        if (!themes.realmExists(realmId)) {
            return ResponseEntity.notFound().build();
        }
        final String name = parse(body);
        if (name != null) {
            final Optional<FileThemeLoader.Result> loaded = files.result(name);
            if (loaded.isEmpty()) {
                throw new ThemeValidationException(Map.of("themeName", files.enabled()
                        ? "No file theme named " + name + " is mounted in " + FileThemeRegistry.DIRECTORY + "."
                        : "File themes are not enabled: " + FileThemeRegistry.DIRECTORY + " is not set."));
            }
            if (!loaded.get().valid()) {
                throw new ThemeValidationException(Map.of("themeName", "The file theme " + name
                        + " failed validation and cannot be used; see GET /admin/realms/" + realmId
                        + "/theme/base for its problems."));
            }
        }
        final Optional<String> before = themes.selectThemeName(realmId, name);
        if (!Objects.equals(before.orElse(null), name)) {
            AuditContext.attachDetail(request, Map.of("fieldsChanged", "themeName",
                    "themeName", name == null ? "" : name));
        }
        return ResponseEntity.ok(view(name));
    }

    private Selection view(final String name) {
        final List<Available> available = files.results().values().stream()
                .map(r -> new Available(r.name(), r.valid(), r.problems()))
                .toList();
        final String status;
        if (name == null) {
            status = "none";
        } else {
            status = files.result(name).map(r -> r.valid() ? "active" : "refused").orElse("missing");
        }
        return new Selection(name, status, files.enabled(), available);
    }

    /** {@code {"themeName": string|null}}; anything else is a 400 naming the field. */
    private static String parse(final JsonNode body) {
        if (body == null || !body.isObject()) {
            throw new ThemeValidationException(Map.of("themeName", "The body must be {\"themeName\": \"<name>\"} or"
                    + " {\"themeName\": null}."));
        }
        for (final Iterator<String> it = body.fieldNames(); it.hasNext(); ) {
            final String field = it.next();
            if (!"themeName".equals(field)) {
                throw new ThemeValidationException(Map.of(field, "Unknown field."));
            }
        }
        final JsonNode value = body.get("themeName");
        if (value == null || value.isNull() || value.isTextual() && value.asText().isBlank()) {
            return null;
        }
        if (!value.isTextual() || !FileThemeLoader.NAME.matcher(value.asText().trim()).matches()) {
            throw new ThemeValidationException(Map.of("themeName", "A theme name is 1-64 letters, digits, '.', '_' or"
                    + " '-', starting with a letter or digit."));
        }
        return value.asText().trim();
    }
}
