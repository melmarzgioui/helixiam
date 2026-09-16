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

    @Autowired
    public RealmIoController(final RealmExportService exportService, final RealmImportService importService) {
        this.exportService = exportService;
        this.importService = importService;
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
        return ResponseEntity.ok(importService.importInto(realmId, document, options));
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
        return ResponseEntity.ok(importService.importInto(realmId, document));
    }

    /** Keeps a realm id safe to drop into a Content-Disposition filename. */
    private static String safeFilename(final String realmId) {
        if (realmId == null || realmId.isBlank()) {
            return "realm";
        }
        return realmId.replaceAll("[^A-Za-z0-9._-]", "_");
    }
}
