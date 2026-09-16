package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.role.RoleAdminPublisher;
import io.helixiam.authorization.amqp.role.RoleAssignment;
import io.helixiam.authorization.amqp.role.RoleDto;
import io.helixiam.authorization.amqp.role.RoleRef;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM E8.5-S2: admin REST API for realm roles and per-user role assignment — the backend behind
 * the console's Realm roles screen and the user role manager. Realm always comes from the path.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}")
@Tag(name = "Roles", description = "Realm roles and per-user role assignment.")
public class RoleAdminController {

    private final RoleAdminPublisher publisher;

    public RoleAdminController(final RoleAdminPublisher publisher) {
        this.publisher = publisher;
    }

    // ----- Realm roles -----

    @GetMapping("/roles")
    @Operation(summary = "List realm roles", description = "All roles defined in the realm.")
    public List<RoleDto> list(@PathVariable final String realmId) {
        return publisher.list(realmId);
    }

    @PostMapping("/roles")
    @Operation(summary = "Create a realm role")
    public ResponseEntity<RoleDto> create(@PathVariable final String realmId, @Valid @RequestBody final RoleNameRequest request) {
        final RoleDto saved = publisher.create(new RoleRef(realmId, null, request.name()));
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @DeleteMapping("/roles/{roleId}")
    @Operation(summary = "Delete a realm role", description = "Remove a role; 400 for a protected system role, 404 if absent.")
    public ResponseEntity<?> delete(@PathVariable final String realmId, @PathVariable final String roleId) {
        // Protected system roles (admin/user/auditor) can't be deleted. Rejected here as a 400 body (rather
        // than a thrown exception) so the response isn't forwarded to the login-redirecting /error dispatch.
        final RoleDto role = publisher.list(realmId).stream()
                .filter(r -> roleId.equals(r.roleId())).findFirst().orElse(null);
        if (role != null && role.system()) {
            return ResponseEntity.badRequest().body(Map.of("message", "System roles cannot be deleted."));
        }
        final boolean removed = Boolean.TRUE.equals(publisher.delete(new RoleRef(realmId, roleId, null)));
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @PutMapping("/roles/{roleId}/default")
    @Operation(summary = "Set the realm's default role",
            description = "Designate the role auto-assigned to new users (clears any prior default). 404 if absent.")
    public ResponseEntity<RoleDto> setDefault(@PathVariable final String realmId, @PathVariable final String roleId) {
        final RoleDto updated = publisher.setDefault(new RoleRef(realmId, roleId, null));
        return updated == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(updated);
    }

    // ----- Per-user assignment -----

    @GetMapping("/users/{userId}/roles")
    @Operation(summary = "List a user's roles", description = "Roles currently assigned to the user.")
    public List<RoleDto> userRoles(@PathVariable final String realmId, @PathVariable final String userId) {
        return publisher.userRoles(new RoleAssignment(realmId, userId, null));
    }

    @PostMapping("/users/{userId}/roles")
    @Operation(summary = "Assign a role", description = "Grant a realm role to the user.")
    public ResponseEntity<Void> assign(@PathVariable final String realmId, @PathVariable final String userId,
                                       @Valid @RequestBody final RoleIdRequest request) {
        final boolean ok = Boolean.TRUE.equals(publisher.assign(new RoleAssignment(realmId, userId, request.roleId())));
        return ok ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @DeleteMapping("/users/{userId}/roles/{roleId}")
    @Operation(summary = "Unassign a role", description = "Revoke a realm role from the user.")
    public ResponseEntity<Void> unassign(@PathVariable final String realmId, @PathVariable final String userId,
                                         @PathVariable final String roleId) {
        final boolean ok = Boolean.TRUE.equals(publisher.unassign(new RoleAssignment(realmId, userId, roleId)));
        return ok ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }
}
