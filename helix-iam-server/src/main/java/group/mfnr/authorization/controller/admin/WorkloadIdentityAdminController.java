package group.mfnr.authorization.controller.admin;

import group.mfnr.authorization.amqp.client.ClientAdminPublisher;
import group.mfnr.authorization.amqp.client.ClientDto;
import group.mfnr.authorization.amqp.workloadidentity.WorkloadIdentityConfigPublisher;
import group.mfnr.authorization.amqp.workloadidentity.WorkloadIdentityCredentialDto;
import group.mfnr.authorization.amqp.workloadidentity.WorkloadIdentityCredentialRef;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
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
 * Helix IAM WIF: admin REST API for per-realm Workload Identity Federation credentials — the backend
 * behind the console's "Workload identity" screen. A credential is a trust policy: it says "a JWT from
 * {@code issuer} with {@code sub}={@code subject} and {@code aud}={@code audience} may exchange for a
 * Helix token acting as {@code clientId}". Nothing here is secret (the whole point of WIF is keyless),
 * so every field round-trips to the console unmasked. The realm comes from the path.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/workload-identity")
public class WorkloadIdentityAdminController {

    private static final Logger LOG = LogManager.getLogger(WorkloadIdentityAdminController.class);

    private final WorkloadIdentityConfigPublisher publisher;
    private final ClientAdminPublisher clientAdminPublisher;

    public WorkloadIdentityAdminController(final WorkloadIdentityConfigPublisher publisher,
                                           final ClientAdminPublisher clientAdminPublisher) {
        this.publisher = publisher;
        this.clientAdminPublisher = clientAdminPublisher;
    }

    /** Editable credential payload from the console (realm + id come from the path). */
    public record WorkloadIdentityRequest(
            @NotBlank(message = "Name is required.") String name,
            @NotBlank(message = "Issuer is required.") String issuer,
            String jwksUri,
            @NotBlank(message = "Subject is required.") String subject,
            @NotBlank(message = "Audience is required.") String audience,
            @NotBlank(message = "Client (the identity the workload acts as) is required.") String clientId,
            String scopes,
            Boolean enabled) {
    }

    @GetMapping
    public List<WorkloadIdentityCredentialDto> list(@PathVariable final String realmId) {
        return publisher.list(realmId);
    }

    @GetMapping("/{id}")
    public ResponseEntity<WorkloadIdentityCredentialDto> get(@PathVariable final String realmId,
                                                             @PathVariable final String id) {
        final WorkloadIdentityCredentialDto dto = publisher.get(new WorkloadIdentityCredentialRef(realmId, id));
        return dto == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(dto);
    }

    @PostMapping
    public ResponseEntity<?> create(@PathVariable final String realmId,
                                    @Valid @RequestBody final WorkloadIdentityRequest body) {
        final String error = validateActsAs(realmId, body.clientId());
        if (error != null) {
            return ResponseEntity.badRequest().body(Map.of("message", error));
        }
        final WorkloadIdentityCredentialDto saved = publisher.save(toDto(null, realmId, body));
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> update(@PathVariable final String realmId, @PathVariable final String id,
                                    @Valid @RequestBody final WorkloadIdentityRequest body) {
        final String error = validateActsAs(realmId, body.clientId());
        if (error != null) {
            return ResponseEntity.badRequest().body(Map.of("message", error));
        }
        return ResponseEntity.ok(publisher.save(toDto(id, realmId, body)));
    }

    /**
     * Guardrail: the "acts as" identity must be a real OIDC client in this realm with its service account
     * enabled, so the minted token's roles/scopes come from a managed identity. Returns an error message,
     * or null when valid. Degrades to null (allow) if the client lookup itself fails, so a transient AMQP
     * hiccup never blocks credential management.
     */
    private String validateActsAs(final String realmId, final String clientId) {
        final List<String> grantTypes;
        try {
            grantTypes = clientAdminPublisher.list(realmId).stream()
                    .filter(c -> clientId.equals(c.clientId()))
                    .map(ClientDto::grantTypes)
                    .findFirst()
                    .orElse(null);
        } catch (final RuntimeException e) {
            LOG.warn("WIF acts-as validation skipped (client lookup failed) for {}: {}", clientId, e.getMessage());
            return null;
        }
        return actsAsError(grantTypes);
    }

    /**
     * Pure validation of an "acts as" client's grant types. {@code null} grant types ⇒ the client doesn't
     * exist; missing {@code client_credentials} ⇒ its service account isn't enabled.
     */
    static String actsAsError(final List<String> grantTypes) {
        if (grantTypes == null) {
            return "The 'acts as' client was not found in this realm — create the Application's OIDC client first.";
        }
        if (!grantTypes.contains("client_credentials")) {
            return "The 'acts as' client must have its service account enabled (the client_credentials grant).";
        }
        return null;
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String id) {
        final boolean removed = Boolean.TRUE.equals(publisher.delete(new WorkloadIdentityCredentialRef(realmId, id)));
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    private static WorkloadIdentityCredentialDto toDto(final String id, final String realmId,
                                                       final WorkloadIdentityRequest body) {
        return new WorkloadIdentityCredentialDto(id, realmId, body.name(), body.issuer(), body.jwksUri(),
                body.subject(), body.audience(), body.clientId(), body.scopes(),
                body.enabled() == null || body.enabled(), null);
    }
}
