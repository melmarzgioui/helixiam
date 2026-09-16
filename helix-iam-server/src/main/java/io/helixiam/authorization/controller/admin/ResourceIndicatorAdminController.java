package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.resource.AllowedResourcesWrite;
import io.helixiam.authorization.amqp.resource.ResourceIndicatorPublisher;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Helix IAM (RFC 8707): admin API for a client's <b>allowed-resource</b> allow-list — the backend behind the
 * console's "Resource indicators" editor on the client detail screen. Stored on the client record (reached
 * over the resource exchange). An empty list clears the allow-list → any requested {@code resource} is
 * accepted (back-compat). Kept off {@code ClientAdminController} so the client write DTO is unchanged.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/clients/{clientId}/allowed-resources")
public class ResourceIndicatorAdminController {

    private final ResourceIndicatorPublisher publisher;

    public ResourceIndicatorAdminController(final ResourceIndicatorPublisher publisher) {
        this.publisher = publisher;
    }

    /** The client's configured allow-list (empty = no allow-list → any resource accepted). */
    @GetMapping
    public List<String> get(@PathVariable final String realmId, @PathVariable final String clientId) {
        return publisher.allowedResourcesForClient(
                io.helixiam.authorization.support.RealmScopedKey.pack(realmId, clientId));
    }

    /** Replace the client's allow-list; 204 on success, 404 when the client does not exist. */
    @PutMapping
    public ResponseEntity<Void> set(@PathVariable final String realmId, @PathVariable final String clientId,
                                    @RequestBody final SetAllowedResourcesRequest request) {
        final List<String> resources = request == null || request.resources() == null ? List.of() : request.resources();
        final boolean ok = Boolean.TRUE.equals(
                publisher.setAllowedResourcesForClient(new AllowedResourcesWrite(realmId, clientId, resources)));
        return ok ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /** Body for {@code PUT} — the absolute resource URIs this client may request via {@code resource}. */
    public record SetAllowedResourcesRequest(List<String> resources) {
    }
}
