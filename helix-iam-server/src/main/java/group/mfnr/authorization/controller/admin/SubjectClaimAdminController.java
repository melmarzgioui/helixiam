package group.mfnr.authorization.controller.admin;

import group.mfnr.authorization.amqp.scope.ClaimScopePublisher;
import group.mfnr.authorization.amqp.scope.SubjectClaimDto;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Helix IAM E8.5: which catalogue claim populates the OIDC {@code sub} for a realm. WSO2's "Subject
 * Attribute" equivalent — pick {@code preferred_username}, {@code email}, {@code phone_number} or any
 * other catalogue claim. Realm comes from the path.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/subject-claim")
public class SubjectClaimAdminController {

    private final ClaimScopePublisher publisher;

    public SubjectClaimAdminController(final ClaimScopePublisher publisher) {
        this.publisher = publisher;
    }

    @GetMapping
    public SubjectClaimDto get(@PathVariable final String realmId) {
        return publisher.subjectClaim(realmId);
    }

    @PutMapping
    public SubjectClaimDto set(@PathVariable final String realmId, @Valid @RequestBody final SubjectClaimRequest request) {
        return publisher.setSubjectClaim(new SubjectClaimDto(realmId, request.claimKey()));
    }

    /** Update body for the realm's subject claim. */
    public record SubjectClaimRequest(@NotBlank(message = "Subject claim key is required.") String claimKey) {
    }
}
