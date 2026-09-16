package group.mfnr.authorization.controller.admin;

import group.mfnr.authorization.idp.provisioning.ProvisioningAdminPublisher;
import group.mfnr.authorization.idp.provisioning.ProvisioningConfigDto;
import group.mfnr.authorization.idp.provisioning.ProvisioningConfigResult;
import group.mfnr.authorization.idp.provisioning.ProvisioningConfigWriteDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Helix IAM E11: admin REST API for a realm's provisioning settings — the backend behind the console's
 * Provisioning screen. Manages the SCIM 2.0 bearer token (rotate/clear; the clear token is returned
 * exactly once on rotate, never stored in clear) and the Dynamic Client Registration policy (open vs
 * gated). Also mints DCR initial access tokens. Realm comes from the path.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/provisioning")
@Tag(name = "Provisioning", description = "SCIM 2.0 token and OIDC Dynamic Client Registration policy for a realm.")
public class ProvisioningAdminController {

    private final ProvisioningAdminPublisher publisher;

    public ProvisioningAdminController(final ProvisioningAdminPublisher publisher) {
        this.publisher = publisher;
    }

    @GetMapping
    @Operation(summary = "Get provisioning config", description = "Current SCIM/DCR settings for the realm (no secrets).")
    public ProvisioningConfigDto get(@PathVariable final String realmId) {
        return publisher.getConfig(realmId);
    }

    /** Update the DCR policy and/or rotate/clear the SCIM token; returns the new token once when rotated. */
    @PutMapping
    @Operation(summary = "Update provisioning config", description = "Set DCR policy and/or rotate/clear the SCIM token; the new token is returned exactly once.")
    public ResponseEntity<ProvisioningConfigResult> save(@PathVariable final String realmId,
                                                         @RequestBody final ProvisioningSaveRequest request) {
        final ProvisioningConfigResult result = publisher.saveConfig(new ProvisioningConfigWriteDto(realmId,
                request.dcrOpen(), request.rotateScimToken(), request.clearScimToken()));
        return ResponseEntity.ok(result);
    }

    /** Mint a single-use DCR initial access token (RFC 7591) for gated registration; returned once. */
    @PostMapping("/initial-access-tokens")
    @Operation(summary = "Mint a DCR initial access token", description = "Single-use RFC 7591 initial access token for gated registration; returned once.")
    public ResponseEntity<InitialAccessTokenResponse> issueInitialAccessToken(@PathVariable final String realmId) {
        return ResponseEntity.ok(new InitialAccessTokenResponse(publisher.issueInitialAccessToken(realmId)));
    }

    /** Save body: {@code dcrOpen} null = leave policy unchanged; the SCIM-token flags are mutually exclusive. */
    public record ProvisioningSaveRequest(Boolean dcrOpen, boolean rotateScimToken, boolean clearScimToken) {
    }

    /** The freshly-minted initial access token (returned exactly once). */
    public record InitialAccessTokenResponse(String initialAccessToken) {
    }
}
