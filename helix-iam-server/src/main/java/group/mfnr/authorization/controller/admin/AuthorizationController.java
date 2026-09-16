package group.mfnr.authorization.controller.admin;

import group.mfnr.authorization.amqp.authz.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Helix IAM (Wave 6): admin REST API for a client's Authorization Services — resource server settings,
 * scopes, resources, role-based policies, permissions, and the Evaluate decision tool.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/clients/{clientId}/authz")
public class AuthorizationController {

    private final AuthorizationPublisher publisher;

    public AuthorizationController(final AuthorizationPublisher publisher) {
        this.publisher = publisher;
    }

    @GetMapping("/settings")
    public AuthzServerDto settings(@PathVariable String realmId, @PathVariable String clientId) {
        return publisher.getServer(new AuthzRef(realmId, clientId, null));
    }

    @PutMapping("/settings")
    public AuthzServerDto saveSettings(@PathVariable String realmId, @PathVariable String clientId, @RequestBody ServerReq r) {
        return publisher.setServer(new AuthzServerDto(realmId, clientId, r.enabled(), r.decisionStrategy()));
    }

    @GetMapping("/scopes")
    public List<AuthzScopeDto> scopes(@PathVariable String realmId, @PathVariable String clientId) {
        return publisher.listScopes(new AuthzRef(realmId, clientId, null));
    }

    @PostMapping("/scopes")
    public ResponseEntity<AuthzScopeDto> createScope(@PathVariable String realmId, @PathVariable String clientId, @Valid @RequestBody NameReq r) {
        return ResponseEntity.status(HttpStatus.CREATED).body(publisher.createScope(new AuthzScopeDto(null, realmId, clientId, r.name())));
    }

    @DeleteMapping("/scopes/{name}")
    public ResponseEntity<Void> deleteScope(@PathVariable String realmId, @PathVariable String clientId, @PathVariable String name) {
        return Boolean.TRUE.equals(publisher.deleteScope(new AuthzRef(realmId, clientId, name)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @GetMapping("/resources")
    public List<AuthzResourceDto> resources(@PathVariable String realmId, @PathVariable String clientId) {
        return publisher.listResources(new AuthzRef(realmId, clientId, null));
    }

    @PostMapping("/resources")
    public ResponseEntity<AuthzResourceDto> createResource(@PathVariable String realmId, @PathVariable String clientId, @Valid @RequestBody ResourceReq r) {
        return ResponseEntity.status(HttpStatus.CREATED).body(
                publisher.createResource(new AuthzResourceDto(null, realmId, clientId, r.name(), r.uris(), r.scopes())));
    }

    @DeleteMapping("/resources/{name}")
    public ResponseEntity<Void> deleteResource(@PathVariable String realmId, @PathVariable String clientId, @PathVariable String name) {
        return Boolean.TRUE.equals(publisher.deleteResource(new AuthzRef(realmId, clientId, name)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @GetMapping("/policies")
    public List<AuthzPolicyDto> policies(@PathVariable String realmId, @PathVariable String clientId) {
        return publisher.listPolicies(new AuthzRef(realmId, clientId, null));
    }

    @PostMapping("/policies")
    public ResponseEntity<AuthzPolicyDto> createPolicy(@PathVariable String realmId, @PathVariable String clientId, @Valid @RequestBody PolicyReq r) {
        return ResponseEntity.status(HttpStatus.CREATED).body(
                publisher.createPolicy(new AuthzPolicyDto(null, realmId, clientId, r.name(), r.type(), r.logic(), r.roles())));
    }

    @DeleteMapping("/policies/{name}")
    public ResponseEntity<Void> deletePolicy(@PathVariable String realmId, @PathVariable String clientId, @PathVariable String name) {
        return Boolean.TRUE.equals(publisher.deletePolicy(new AuthzRef(realmId, clientId, name)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @GetMapping("/permissions")
    public List<AuthzPermissionDto> permissions(@PathVariable String realmId, @PathVariable String clientId) {
        return publisher.listPermissions(new AuthzRef(realmId, clientId, null));
    }

    @PostMapping("/permissions")
    public ResponseEntity<AuthzPermissionDto> createPermission(@PathVariable String realmId, @PathVariable String clientId, @Valid @RequestBody PermissionReq r) {
        return ResponseEntity.status(HttpStatus.CREATED).body(publisher.createPermission(new AuthzPermissionDto(
                null, realmId, clientId, r.name(), r.type(), r.resourceName(), r.scopeName(), r.policies(), r.decisionStrategy())));
    }

    @DeleteMapping("/permissions/{name}")
    public ResponseEntity<Void> deletePermission(@PathVariable String realmId, @PathVariable String clientId, @PathVariable String name) {
        return Boolean.TRUE.equals(publisher.deletePermission(new AuthzRef(realmId, clientId, name)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @PostMapping("/evaluate")
    public AuthzEvalResult evaluate(@PathVariable String realmId, @PathVariable String clientId, @RequestBody EvalReq r) {
        return publisher.evaluate(new AuthzEvalRequest(realmId, clientId, r.username(), r.roles(), r.resourceName(), r.scopeName()));
    }

    public record ServerReq(Boolean enabled, String decisionStrategy) { }
    public record NameReq(@NotBlank(message = "Name is required.") String name) { }
    public record ResourceReq(@NotBlank(message = "Resource name is required.") String name, List<String> uris, List<String> scopes) { }
    public record PolicyReq(@NotBlank(message = "Policy name is required.") String name, String type, String logic, List<String> roles) { }
    public record PermissionReq(@NotBlank(message = "Permission name is required.") String name, String type, String resourceName, String scopeName, List<String> policies, String decisionStrategy) { }
    public record EvalReq(String username, List<String> roles, String resourceName, String scopeName) { }
}
