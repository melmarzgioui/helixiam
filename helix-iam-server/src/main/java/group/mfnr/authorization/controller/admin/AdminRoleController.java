package group.mfnr.authorization.controller.admin;

import group.mfnr.authorization.amqp.adminrbac.AdminPermissionDto;
import group.mfnr.authorization.amqp.adminrbac.AdminRbacPublisher;
import group.mfnr.authorization.amqp.adminrbac.AdminRoleGrantWriteDto;
import group.mfnr.authorization.amqp.adminrbac.AdminRoleGrantsDto;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM: admin REST API for fine-grained admin RBAC — the backend behind the console's "Admin roles"
 * permission matrix. Lists the permission catalogue, lists every realm role with its granted permissions,
 * and sets a role's complete permission set. The realm always comes from the path so grants can't cross realms.
 * <p>
 * No thrown exceptions on these endpoints (the {@code /error} dispatch 302-redirects to login): bad input is
 * surfaced as 400 either by {@link AdminValidationAdvice} ({@code @Valid}) or as a {@code {message}} body.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/admin-roles")
public class AdminRoleController {

    private final AdminRbacPublisher publisher;

    public AdminRoleController(final AdminRbacPublisher publisher) {
        this.publisher = publisher;
    }

    /** The catalogue of admin permissions (matrix columns). */
    @GetMapping("/permissions")
    public List<AdminPermissionDto> permissions(@PathVariable final String realmId) {
        return publisher.catalog(realmId);
    }

    /** Every realm role with the admin-permission keys it grants (matrix rows). */
    @GetMapping
    public List<AdminRoleGrantsDto> roles(@PathVariable final String realmId) {
        return publisher.roles(realmId);
    }

    /** Replace the complete set of admin permissions granted to one role. */
    @PutMapping("/{roleId}")
    public ResponseEntity<?> setPermissions(@PathVariable final String realmId, @PathVariable final String roleId,
                                            @Valid @RequestBody final AdminRoleGrantsRequest request) {
        final AdminRoleGrantsDto saved = publisher.set(
                new AdminRoleGrantWriteDto(realmId, roleId, request.permissions()));
        if (saved == null) {
            // Subscriber rejected (unknown permission / cross-realm role). Return 400, never throw.
            return ResponseEntity.badRequest().body(Map.of("message",
                    "Could not set permissions: the role is unknown for this realm or a permission is invalid."));
        }
        return ResponseEntity.ok(saved);
    }

    /** Body for setting a role's complete admin-permission set (permission keys, possibly empty but not null). */
    public record AdminRoleGrantsRequest(@NotNull(message = "permissions is required") List<String> permissions) {
    }
}
