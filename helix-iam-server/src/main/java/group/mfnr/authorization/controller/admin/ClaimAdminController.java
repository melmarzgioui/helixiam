package group.mfnr.authorization.controller.admin;

import group.mfnr.authorization.amqp.scope.ClaimDto;
import group.mfnr.authorization.amqp.scope.ClaimScopePublisher;
import group.mfnr.authorization.amqp.scope.ClaimWriteDto;
import group.mfnr.authorization.amqp.scope.ScopeRef;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
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

/**
 * Helix IAM E8.5: admin REST API for a realm's claim catalogue — the master list of claim types the
 * console's Claims screen manages (and scopes map from). Realm comes from the path.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/claims")
public class ClaimAdminController {

    private final ClaimScopePublisher publisher;

    public ClaimAdminController(final ClaimScopePublisher publisher) {
        this.publisher = publisher;
    }

    @GetMapping
    public List<ClaimDto> list(@PathVariable final String realmId) {
        return publisher.claims(realmId);
    }

    @PostMapping
    public ResponseEntity<ClaimDto> create(@PathVariable final String realmId, @Valid @RequestBody final ClaimRequest request) {
        final ClaimDto saved = publisher.createClaim(new ClaimWriteDto(realmId, null, request.key(), request.label(), blankToNull(request.placeholder()), request.mandatory()));
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @PutMapping("/{claimId}")
    public ResponseEntity<ClaimDto> update(@PathVariable final String realmId, @PathVariable final String claimId,
                                           @Valid @RequestBody final ClaimRequest request) {
        final ClaimDto saved = publisher.updateClaim(new ClaimWriteDto(realmId, claimId, request.key(), request.label(), blankToNull(request.placeholder()), request.mandatory()));
        return saved == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(saved);
    }

    @DeleteMapping("/{claimId}")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String claimId) {
        return Boolean.TRUE.equals(publisher.deleteClaim(new ScopeRef(realmId, null, claimId)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    private static String blankToNull(final String value) {
        return value == null || value.isBlank() ? null : value;
    }

    /** Create/update body for a catalogue claim. */
    public record ClaimRequest(@NotBlank(message = "Claim key is required.") String key,
                               @NotBlank(message = "Claim label is required.") String label,
                               String placeholder, boolean mandatory) {
    }
}
