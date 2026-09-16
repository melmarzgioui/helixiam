package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.agent.AgentIdentityDto;
import io.helixiam.authorization.amqp.agent.AgentIdentityPublisher;
import io.helixiam.authorization.amqp.agent.AgentIdentityRef;
import io.helixiam.authorization.amqp.agent.AgentOwnerReviewDto;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
 * Helix IAM Agent (NHI): admin REST API for the per-realm agent registry — the backend behind the console's
 * "Agents" screen. An agent is a first-class non-human identity (automation, service, AI agent) owned by an
 * accountable human, carrying a lifecycle {@code status} and an {@code authMethod}. The registry record is
 * non-secret, so every field round-trips to the console unmasked. The realm comes from the path. This
 * controller never throws out of a write endpoint (a thrown error 302-redirects to login via the security
 * {@code /error} dispatch) — it returns {@link ResponseEntity} and relies on {@link AdminValidationAdvice}
 * for 400s. Token issuance and claim enrichment are wired separately.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/agents")
public class AgentIdentityAdminController {

    private static final Logger LOG = LogManager.getLogger(AgentIdentityAdminController.class);

    private final AgentIdentityPublisher publisher;

    public AgentIdentityAdminController(final AgentIdentityPublisher publisher) {
        this.publisher = publisher;
    }

    /** Editable agent payload from the console (realm + id come from the path). */
    public record AgentRequest(
            @NotBlank(message = "Name is required.")
            @Pattern(regexp = "[A-Za-z0-9._:-]+", message = "Name must not contain spaces.") String name,
            String displayName,
            String description,
            @NotBlank(message = "Owner (the accountable human) is required.") String owner,
            @Pattern(regexp = "ACTIVE|SUSPENDED|EXPIRED|REVOKED",
                    message = "Status must be one of ACTIVE, SUSPENDED, EXPIRED, REVOKED.") String status,
            @Pattern(regexp = "FEDERATED|SECRET|JWT",
                    message = "Auth method must be one of FEDERATED, SECRET, JWT.") String authMethod,
            String clientId,
            String scopes,
            String roles,
            Boolean enabled,
            Long expiresAt) {
    }

    @GetMapping
    public List<AgentIdentityDto> list(@PathVariable final String realmId) {
        return publisher.list(realmId);
    }

    /** Owner-integrity review: every agent tagged VALID/UNKNOWN/ORPHANED against the realm's users. */
    @GetMapping("/owner-review")
    public List<AgentOwnerReviewDto> ownerReview(@PathVariable final String realmId) {
        return publisher.ownerReview(realmId);
    }

    @GetMapping("/{id}")
    public ResponseEntity<AgentIdentityDto> get(@PathVariable final String realmId, @PathVariable final String id) {
        final AgentIdentityDto dto = publisher.get(new AgentIdentityRef(realmId, id));
        return dto == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(dto);
    }

    @PostMapping
    public ResponseEntity<?> create(@PathVariable final String realmId,
                                    @Valid @RequestBody final AgentRequest body) {
        try {
            final AgentIdentityDto saved = publisher.save(toDto(null, realmId, body));
            return ResponseEntity.status(HttpStatus.CREATED).body(saved);
        } catch (final RuntimeException e) {
            LOG.warn("Agent create failed in realm {}: {}", realmId, e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("message", "Could not create the agent (the name may already be in use)."));
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> update(@PathVariable final String realmId, @PathVariable final String id,
                                    @Valid @RequestBody final AgentRequest body) {
        try {
            return ResponseEntity.ok(publisher.save(toDto(id, realmId, body)));
        } catch (final RuntimeException e) {
            LOG.warn("Agent update failed for {} in realm {}: {}", id, realmId, e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("message", "Could not update the agent (the name may already be in use)."));
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String id) {
        final boolean removed = Boolean.TRUE.equals(publisher.delete(new AgentIdentityRef(realmId, id)));
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @PostMapping("/{id}/suspend")
    public ResponseEntity<AgentIdentityDto> suspend(@PathVariable final String realmId, @PathVariable final String id) {
        final AgentIdentityDto dto = publisher.suspend(new AgentIdentityRef(realmId, id));
        return dto == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(dto);
    }

    @PostMapping("/{id}/activate")
    public ResponseEntity<AgentIdentityDto> activate(@PathVariable final String realmId, @PathVariable final String id) {
        final AgentIdentityDto dto = publisher.activate(new AgentIdentityRef(realmId, id));
        return dto == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(dto);
    }

    @PostMapping("/{id}/revoke")
    public ResponseEntity<AgentIdentityDto> revoke(@PathVariable final String realmId, @PathVariable final String id) {
        final AgentIdentityDto dto = publisher.revoke(new AgentIdentityRef(realmId, id));
        return dto == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(dto);
    }

    private static AgentIdentityDto toDto(final String id, final String realmId, final AgentRequest body) {
        return new AgentIdentityDto(id, realmId, body.name(), body.displayName(), body.description(),
                body.owner(), body.status(), body.authMethod(), body.clientId(), body.scopes(),
                body.enabled() == null || body.enabled(), null, body.expiresAt(), null, body.roles());
    }
}
