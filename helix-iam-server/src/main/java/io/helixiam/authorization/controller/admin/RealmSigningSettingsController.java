/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.service.key.RealmSigningSettingsService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Set;

/**
 * A realm's signing algorithms (realm settings → Signing): {@code defaultAlg} for access tokens, logout tokens,
 * delegation and workload-identity tokens and JARM (ID tokens follow each client's {@code id_token_signed_response_alg});
 * {@code samlAlg} for SAML. Choosing ES256 needs an ACTIVE EC key; anything invalid is
 * {@code 400 {message, fieldErrors}}. Audited as {@code REALM_UPDATE}.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/settings/signing")
public class RealmSigningSettingsController {

    private final RealmSigningSettingsService service;
    private final io.helixiam.authorization.service.key.KeyMaterialService keys;
    private final io.helixiam.authorization.security.adminrbac.AdminAuthorizationManager rbac;

    public RealmSigningSettingsController(final RealmSigningSettingsService service,
                                          final io.helixiam.authorization.service.key.KeyMaterialService keys,
                                          final io.helixiam.authorization.security.adminrbac.AdminAuthorizationManager rbac) {
        this.service = service;
        this.keys = keys;
        this.rbac = rbac;
    }

    /** The settings plus the algorithms the realm's ACTIVE keys can sign (for the console's choices). */
    public record SigningSettingsView(String defaultAlg, String samlAlg, Set<String> activeAlgorithms) {
    }

    public record SigningSettingsWrite(String defaultAlg, String samlAlg) {
    }

    @GetMapping
    public SigningSettingsView get(@PathVariable final String realmId) {
        final RealmSigningSettingsService.Settings s = service.get(realmId);
        return new SigningSettingsView(s.defaultAlg(), s.samlAlg(), keys.activeAlgorithms(realmId));
    }

    @PutMapping
    public org.springframework.http.ResponseEntity<?> put(@PathVariable final String realmId,
                                                          @RequestBody final SigningSettingsWrite body,
                                                          final HttpServletRequest http) {
        // Defence in depth: which key and algorithm sign is realm-admin territory, like key writes.
        if (!rbac.permits(org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication(),
                realmId, io.helixiam.authorization.security.adminrbac.AdminRoutePermissions.REALM_ADMIN)) {
            return org.springframework.http.ResponseEntity.status(org.springframework.http.HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "forbidden", "message", "Changing the signing settings needs realm-admin."));
        }
        final Map<String, String> errors = service.put(realmId, body == null ? null : body.defaultAlg(),
                body == null ? null : body.samlAlg());
        if (!errors.isEmpty()) {
            throw new ProviderValidationException(errors);
        }
        final RealmSigningSettingsService.Settings s = service.get(realmId);
        AuditContext.attachDetail(http, Map.of("signing.defaultAlg", s.defaultAlg(), "signing.samlAlg", s.samlAlg()));
        return org.springframework.http.ResponseEntity.ok(
                new SigningSettingsView(s.defaultAlg(), s.samlAlg(), keys.activeAlgorithms(realmId)));
    }
}
