/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.theme.ThemeService;
import io.helixiam.authorization.theme.asset.ThemeAssetInUseException;
import io.helixiam.authorization.theme.asset.ThemeAssetMetadata;
import io.helixiam.authorization.theme.asset.ThemeAssetService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Theme fonts and images (spec §3, §7), all under {@code manage-realm} ({@code AdminRoutePermissions}: the
 * {@code theme} group).
 * <ul>
 *   <li>{@code POST /admin/realms/{r}/theme/assets} (multipart: {@code file}; for a font also {@code name}, and
 *       optionally {@code weight} and {@code style}) → {@code 201} with the metadata, or
 *       {@code 400 {message, fieldErrors}} when the file or a realm limit refuses it.</li>
 *   <li>{@code GET /admin/realms/{r}/theme/assets} → the metadata list (id, kind, name, ext, size, sha256, created,
 *       url; never bytes).</li>
 *   <li>{@code DELETE /admin/realms/{r}/theme/assets/{id}} → {@code 204}; {@code 404} for an id of another realm;
 *       {@code 409 {message, references}} while a realm or organization theme still uses it.</li>
 * </ul>
 * Uploads and deletions are audited with the asset's metadata, never its bytes.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/theme/assets")
@Tag(name = "Theme", description = "Structured realm and organization theming")
public class ThemeAssetAdminController {

    private final ThemeAssetService assets;
    private final ThemeService themes;

    public ThemeAssetAdminController(final ThemeAssetService assets, final ThemeService themes) {
        this.assets = assets;
        this.themes = themes;
    }

    @GetMapping
    @Operation(summary = "The realm's uploaded fonts and images (metadata only)")
    public ResponseEntity<List<ThemeAssetMetadata>> list(@PathVariable final String realmId) {
        if (!themes.realmExists(realmId)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(assets.list(realmId));
    }

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Upload a font (woff2) or an image (svg, png, webp)")
    public ResponseEntity<ThemeAssetMetadata> upload(@PathVariable final String realmId,
                                                     @RequestParam("file") final MultipartFile file,
                                                     @RequestParam(name = "name", required = false) final String name,
                                                     @RequestParam(name = "weight", required = false) final String weight,
                                                     @RequestParam(name = "style", required = false) final String style,
                                                     final HttpServletRequest request) throws IOException {
        if (!themes.realmExists(realmId)) {
            return ResponseEntity.notFound().build();
        }
        final ThemeAssetMetadata m = assets.upload(realmId, file.getOriginalFilename(), file.getBytes(), name, weight,
                style);
        AuditContext.attachDetail(request, detail(m));
        return ResponseEntity.status(HttpStatus.CREATED).body(m);
    }

    @DeleteMapping("/{assetId}")
    @Operation(summary = "Delete an uploaded font or image (409 while a theme uses it)")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String assetId,
                                       final HttpServletRequest request) {
        return assets.delete(realmId, assetId)
                .map(m -> {
                    AuditContext.attachDetail(request, detail(m));
                    return ResponseEntity.noContent().<Void>build();
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** A referenced asset: {@code 409 {message, references}}. */
    @ExceptionHandler(ThemeAssetInUseException.class)
    public ResponseEntity<Map<String, Object>> inUse(final ThemeAssetInUseException e) {
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", e.getMessage() + " Change those fields first.");
        body.put("references", e.references());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
    }

    /** Not a multipart request, or no {@code file} part: {@code 400 {message, fieldErrors}}. */
    @ExceptionHandler({MultipartException.class, MissingServletRequestPartException.class,
            MissingServletRequestParameterException.class})
    public ResponseEntity<Map<String, Object>> noFile(final Exception e) {
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", "Send the file as multipart/form-data in a part named \"file\".");
        body.put("fieldErrors", Map.of("file", "A file is required."));
        return ResponseEntity.badRequest().body(body);
    }

    private static Map<String, String> detail(final ThemeAssetMetadata m) {
        final Map<String, String> d = new LinkedHashMap<>();
        d.put("assetId", m.id());
        d.put("kind", m.kind().key());
        d.put("name", m.name());
        d.put("ext", m.ext());
        d.put("size", Integer.toString(m.size()));
        d.put("sha256", m.sha256());
        return d;
    }
}
