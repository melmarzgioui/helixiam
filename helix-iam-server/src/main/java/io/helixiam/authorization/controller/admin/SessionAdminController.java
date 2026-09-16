package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.session.IdentitySessionView;
import io.helixiam.authorization.session.SessionAdminService;
import io.helixiam.authorization.session.SessionSummary;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Helix IAM SSO P7 / Sessions v2: admin REST API for a realm's active identities — the backend behind the
 * console's Sessions screen. {@code GET /sessions?q=&type=} returns one unified, filtered row per active
 * identity (user / agent / service account), each resolved to a display name + identity type;
 * {@code DELETE /sessions/{id}} cascades a Single Logout for interactive sessions or revokes a
 * service-account token, dispatched by {@link SessionAdminService#revokeIdentity}.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/sessions")
public class SessionAdminController {

    private final SessionAdminService service;

    public SessionAdminController(final SessionAdminService service) {
        this.service = service;
    }

    @GetMapping
    public List<IdentitySessionView> list(@PathVariable final String realmId,
                                          @RequestParam(required = false) final String q,
                                          @RequestParam(required = false) final String type) {
        return service.listIdentities(realmId, q, type);
    }

    @GetMapping("/service-accounts")
    public List<SessionSummary> serviceAccounts(@PathVariable final String realmId) {
        return service.listServiceAccounts(realmId);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> revoke(@PathVariable final String realmId, @PathVariable final String id) {
        return service.revokeIdentity(realmId, id) ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }
}
