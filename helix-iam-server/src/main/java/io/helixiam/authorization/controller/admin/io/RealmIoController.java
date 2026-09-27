/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin.io;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Helix IAM: realm import/export — the backend behind the console's "Import / export" screen.
 *
 * <p>{@code GET /admin/realms/{realmId}/export} returns a single JSON document bundling
 * every configurable slice of the realm (settings, OIDC clients, SAML relying parties, roles, client
 * scopes + claims, identity providers, auth flows, organizations) with all secrets masked. {@code POST
 * /admin/realms/{realmId}/import} accepts that document and idempotently upserts it into the realm,
 * returning a per-slice {@code {created, updated, skipped}} summary.
 *
 * <p>Realm comes from the path; the document's own realm id is ignored, so an export can be re-homed into
 * a different realm. Both endpoints are pure publisher-side orchestration over the existing per-domain
 * admin publishers (no new AMQP exchange). Never throws: malformed JSON is turned into a clean 400 by
 * {@link io.helixiam.authorization.controller.admin.AdminValidationAdvice} (a thrown exception here would
 * route through the security-guarded {@code /error} dispatch and 302-redirect to login).
 */
@RestController
@RequestMapping("/admin/realms/{realmId}")
public class RealmIoController {

    private final RealmExportService exportService;
    private final RealmImportService importService;
    private RealmArchiveService archiveService;

    @Autowired
    public RealmIoController(final RealmExportService exportService, final RealmImportService importService) {
        this.exportService = exportService;
        this.importService = importService;
    }

    /** Review I2: the optional archive (document + theme asset bytes). */
    @Autowired(required = false)
    public void setArchiveService(final RealmArchiveService archiveService) {
        this.archiveService = archiveService;
    }

    /**
     * Spec §7 "optional archive export": {@code GET /export?includeAssets=true} returns a zip with
     * {@code realm-export.json}, {@code theme-assets/manifest.json} and {@code theme-assets/{id}.{ext}}.
     */
    @GetMapping(value = "/export", params = "includeAssets=true")
    public ResponseEntity<byte[]> exportArchive(@PathVariable final String realmId) {
        if (archiveService == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/zip"))
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + safeFilename(realmId) + "-realm-export.zip\"")
                .body(archiveService.export(realmId));
    }

    /**
     * Imports an archive made by {@link #exportArchive}: every asset is re-uploaded through the normal upload rules
     * (sha256 checked against the manifest), asset URLs in the themes are rewritten to the new ids, then the document
     * is imported as by the JSON endpoint. A malformed or inconsistent archive is a 400 and imports nothing.
     */
    @PostMapping(value = "/import", consumes = {"application/zip", "application/x-zip-compressed"})
    public ResponseEntity<RealmImportResult> importArchive(@PathVariable final String realmId,
                                                           @RequestParam(name = "onConflict", required = false)
                                                           final String onConflict,
                                                           final jakarta.servlet.http.HttpServletRequest request)
            throws java.io.IOException {
        if (archiveService == null) {
            return ResponseEntity.notFound().build();
        }
        final ImportOptions options = new ImportOptions(ImportOptions.conflictOf(onConflict));
        return respond(archiveService.importArchive(realmId, request.getInputStream(), options,
                io.helixiam.authorization.security.audit.AuditContext.clientIp(request)));
    }

    /** A malformed, oversized or inconsistent archive: {@code 400 {message, fieldErrors}}. */
    @org.springframework.web.bind.annotation.ExceptionHandler(RealmArchiveException.class)
    public ResponseEntity<java.util.Map<String, Object>> badArchive(final RealmArchiveException e) {
        final java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("message", e.getMessage());
        body.put("fieldErrors", java.util.Map.of("archive", e.getMessage()));
        return ResponseEntity.badRequest().body(body);
    }

    /** The full, secret-masked realm export as a downloadable JSON document. */
    @GetMapping("/export")
    public ResponseEntity<RealmExportDocument> export(@PathVariable final String realmId) {
        final RealmExportDocument doc = exportService.export(realmId);
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + safeFilename(realmId) + "-realm-export.json\"")
                .body(doc);
    }

    /**
     * Applies the document into the realm and returns the per-slice summary. {@code onConflict} chooses how
     * existing entries are treated: {@code overwrite} (default — upsert), {@code skip} (block: leave existing
     * untouched), or {@code fail} (block and list each conflict). Secret {@code ${ENV_VAR}} placeholders are
     * resolved from the environment.
     */
    @PostMapping("/import")
    public ResponseEntity<RealmImportResult> importRealm(@PathVariable final String realmId,
                                                         @RequestParam(name = "onConflict", required = false)
                                                         final String onConflict,
                                                         @RequestBody final RealmExportDocument document) {
        final ImportOptions options = new ImportOptions(ImportOptions.conflictOf(onConflict));
        return respond(importService.importInto(realmId, document, options));
    }

    /**
     * PROD-5: migrate off Keycloak. Accepts a Keycloak realm-export JSON, translates the portable slices
     * (OIDC clients with derived grant types, realm roles, identity providers) into Helix's import document
     * via {@link KeycloakImporter}, and upserts it. Users are not migrated (Keycloak password hashes aren't
     * portable) — bring them via SCIM / LDAP sync / bulk import. Realm comes from the path.
     */
    @PostMapping("/import/keycloak")
    public ResponseEntity<RealmImportResult> importKeycloak(@PathVariable final String realmId,
                                                            @RequestBody final com.fasterxml.jackson.databind.JsonNode keycloakExport) {
        final RealmExportDocument document = KeycloakImporter.translate(keycloakExport);
        return respond(importService.importInto(realmId, document));
    }

    /** 1.0 item 8: 200 when everything applied; 422 (same body, with {@code failed[]}) when any entry failed. */
    private static ResponseEntity<RealmImportResult> respond(final RealmImportResult result) {
        return result.hasFailures() ? ResponseEntity.unprocessableEntity().body(result) : ResponseEntity.ok(result);
    }

    /** Keeps a realm id safe to drop into a Content-Disposition filename. */
    private static String safeFilename(final String realmId) {
        if (realmId == null || realmId.isBlank()) {
            return "realm";
        }
        return realmId.replaceAll("[^A-Za-z0-9._-]", "_");
    }
}
