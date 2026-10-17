/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.security.adminrbac.AdminAuthorizationManager;
import io.helixiam.authorization.security.adminrbac.AdminRoutePermissions;
import io.helixiam.authorization.service.federation.FederatedLinkTrustService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Round 6: a user's linked identities in the admin console, with how each was made. A realm admin can confirm a link
 * ({@code ADMIN_CONFIRMED}: it may sign in an administrator) or revoke trust in it ({@code AUTO}: it never signs in an
 * administrator). {@code canManageTrust} tells the console whether to show those actions.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/users/{userId}/federated-identities")
public class UserFederatedIdentityAdminController {

    private final FederatedLinkTrustService trust;
    private final AdminAuthorizationManager rbac;

    public UserFederatedIdentityAdminController(final FederatedLinkTrustService trust,
                                                final AdminAuthorizationManager rbac) {
        this.trust = trust;
        this.rbac = rbac;
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> list(@PathVariable final String realmId,
                                                    @PathVariable final String userId) {
        final List<FederatedLinkTrustService.LinkView> links = trust.list(realmId, userId);
        if (links == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(Map.of("identities", links, "canManageTrust", realmAdmin(realmId)));
    }

    /** Which one link: a user may have several links of one provider (one per external subject). */
    public record LinkRef(@jakarta.validation.constraints.NotBlank(message = "externalSubject is required.")
                          String externalSubject) {
    }

    @PostMapping("/{alias}/confirm")
    public ResponseEntity<?> confirm(@PathVariable final String realmId, @PathVariable final String userId,
                                     @PathVariable final String alias,
                                     @jakarta.validation.Valid @org.springframework.web.bind.annotation.RequestBody
                                     final LinkRef link) {
        if (!realmAdmin(realmId)) {
            return forbidden();
        }
        return trust.confirm(realmId, userId, alias, link.externalSubject()) ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }

    @PostMapping("/{alias}/revoke-trust")
    public ResponseEntity<?> revokeTrust(@PathVariable final String realmId, @PathVariable final String userId,
                                         @PathVariable final String alias,
                                         @jakarta.validation.Valid @org.springframework.web.bind.annotation.RequestBody
                                         final LinkRef link) {
        if (!realmAdmin(realmId)) {
            return forbidden();
        }
        return trust.revokeTrust(realmId, userId, alias, link.externalSubject()) ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }

    private boolean realmAdmin(final String realmId) {
        return rbac.permits(SecurityContextHolder.getContext().getAuthentication(), realmId,
                AdminRoutePermissions.REALM_ADMIN);
    }

    private static ResponseEntity<Map<String, String>> forbidden() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "forbidden",
                "message", "Confirming or revoking trust in a federated link needs realm-admin."));
    }
}
