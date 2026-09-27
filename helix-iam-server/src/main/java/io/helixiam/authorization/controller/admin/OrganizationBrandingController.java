/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.service.org.OrganizationBrandingService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 1.0 item 7 (branding): an organization's display name, logo and primary colour, shown on the sign-in pages when
 * the organization is in context. Values are validated strictly — a {@code #RRGGBB} colour, an {@code https} logo
 * URL, plain-text name — so no CSS or HTML can be injected into the pages. PUT replaces all three.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/organizations/{orgId}/branding")
public class OrganizationBrandingController {

    private final OrganizationBrandingService branding;

    public OrganizationBrandingController(final OrganizationBrandingService branding) {
        this.branding = branding;
    }

    @GetMapping
    public ResponseEntity<OrganizationBrandingService.Branding> get(@PathVariable final String realmId,
                                                                    @PathVariable final String orgId) {
        return branding.get(realmId, orgId).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PutMapping
    public ResponseEntity<OrganizationBrandingService.Branding> put(@PathVariable final String realmId,
                                                                    @PathVariable final String orgId,
                                                                    @Valid @RequestBody final Body body) {
        return branding.replace(realmId, orgId, new OrganizationBrandingService.Branding(body.displayName(),
                        body.logoUrl(), body.primaryColor()))
                .map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    public record Body(
            @Size(max = 100, message = "Display name must be at most 100 characters.")
            @Pattern(regexp = "[^<>]*", message = "Display name cannot contain < or >.") String displayName,
            @Size(max = 2048, message = "Logo URL must be at most 2048 characters.")
            @Pattern(regexp = "https://[^\\s\"'<>()\\\\]+", message = "Logo URL must be an https URL.") String logoUrl,
            @Pattern(regexp = "#[0-9a-fA-F]{6}", message = "Primary colour must be #RRGGBB.") String primaryColor) {
    }
}
