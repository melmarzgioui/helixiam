/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.clientrole.ClientRoleDto;
import io.helixiam.authorization.amqp.clientrole.ClientRolePublisher;
import io.helixiam.authorization.amqp.clientrole.ClientRoleRef;
import io.helixiam.authorization.amqp.clientrole.ClientRoleWriteDto;
import io.helixiam.authorization.amqp.clientrole.ServiceAccountRoleDto;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Helix IAM (Wave 4): admin REST API for a client's roles + its service-account role grants. {@code id} in
 * the path is the client's {@code clientId}.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/clients/{clientId}")
public class ClientRoleController {

    private final ClientRolePublisher publisher;

    public ClientRoleController(final ClientRolePublisher publisher) {
        this.publisher = publisher;
    }

    // --- Client roles ---

    @GetMapping("/roles")
    public List<ClientRoleDto> listRoles(@PathVariable final String realmId, @PathVariable final String clientId) {
        return publisher.listRoles(new ClientRoleRef(realmId, clientId, null));
    }

    @PostMapping("/roles")
    public ResponseEntity<ClientRoleDto> createRole(@PathVariable final String realmId, @PathVariable final String clientId,
                                                    @Valid @RequestBody final ClientRoleRequest request) {
        final ClientRoleDto saved = publisher.createRole(new ClientRoleWriteDto(realmId, clientId, request.name(), request.description()));
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @DeleteMapping("/roles/{name}")
    public ResponseEntity<Void> deleteRole(@PathVariable final String realmId, @PathVariable final String clientId,
                                           @PathVariable final String name) {
        final boolean removed = Boolean.TRUE.equals(publisher.deleteRole(new ClientRoleRef(realmId, clientId, name)));
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /** Security review (rc.11): the role's admin permissions must be the caller's own (also checked in the service). */
    private io.helixiam.authorization.service.adminrbac.AdminGrantGuard adminGrantGuard;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setAdminGrantGuard(final io.helixiam.authorization.service.adminrbac.AdminGrantGuard adminGrantGuard) {
        this.adminGrantGuard = adminGrantGuard;
    }

    // --- Service-account roles ---

    @GetMapping("/service-account/roles")
    public List<ServiceAccountRoleDto> listSaRoles(@PathVariable final String realmId, @PathVariable final String clientId) {
        return publisher.listServiceAccountRoles(new ClientRoleRef(realmId, clientId, null));
    }

    @PostMapping("/service-account/roles")
    public ResponseEntity<ServiceAccountRoleDto> assignSaRole(@PathVariable final String realmId, @PathVariable final String clientId,
                                                              @Valid @RequestBody final SaRoleRequest request) {
        if (adminGrantGuard != null && (request.roleType() == null || "REALM".equalsIgnoreCase(request.roleType()))) {
            adminGrantGuard.requireMayGrant(realmId, adminGrantGuard.grantsOfName(realmId, request.roleName()), "This role");
        }
        final ServiceAccountRoleDto saved = publisher.assignServiceAccountRole(new ServiceAccountRoleDto(
                null, realmId, clientId, request.roleName(), request.roleType(), request.roleClientId()));
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @DeleteMapping("/service-account/roles")
    public ResponseEntity<Void> unassignSaRole(@PathVariable final String realmId, @PathVariable final String clientId,
                                               @RequestParam final String roleName,
                                               @RequestParam(required = false, defaultValue = "REALM") final String roleType) {
        final boolean removed = Boolean.TRUE.equals(publisher.unassignServiceAccountRole(
                new ServiceAccountRoleDto(null, realmId, clientId, roleName, roleType, null)));
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /** "FACTOR_" is Spring Security 7's sign-in factor namespace: never a role (SignInAuthorities). */
    public record ClientRoleRequest(@NotBlank(message = "Role name is required.")
                                    @jakarta.validation.constraints.Pattern(regexp = "(?is)(?!factor_).*",
                                            message = "Role names starting with 'FACTOR_' are reserved.") String name,
                                    String description) {
    }

    public record SaRoleRequest(@NotBlank(message = "Role name is required.")
                                @jakarta.validation.constraints.Pattern(regexp = "(?is)(?!factor_).*",
                                        message = "Role names starting with 'FACTOR_' are reserved.") String roleName,
                                String roleType, String roleClientId) {
    }
}
