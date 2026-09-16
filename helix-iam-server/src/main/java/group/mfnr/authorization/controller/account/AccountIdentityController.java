package group.mfnr.authorization.controller.account;

import group.mfnr.authorization.amqp.account.AccountIdentityPublisher;
import group.mfnr.authorization.amqp.account.AccountUnlinkRef;
import group.mfnr.authorization.amqp.account.FederatedLinkDto;
import group.mfnr.authorization.domain.UserCredentials;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Helix IAM B9: the end-user account console's "Connected accounts" — the signed-in user views the
 * identity providers their account is linked through (Google, DigiD, …) and disconnects any of them.
 * Like the rest of {@code /account/**}, every operation is pinned to the authenticated principal's userId,
 * so a user can only ever see and unlink <em>their own</em> federated logins.
 */
@RestController
@RequestMapping("/account/identities")
public class AccountIdentityController {

    private final AccountIdentityPublisher publisher;

    public AccountIdentityController(final AccountIdentityPublisher publisher) {
        this.publisher = publisher;
    }

    /** The caller's connected federated identities. 401 when unauthenticated. */
    @GetMapping
    public ResponseEntity<List<FederatedLinkDto>> list(@AuthenticationPrincipal final UserCredentials principal) {
        if (principal == null || principal.getUserId() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        final List<FederatedLinkDto> links = publisher.list(principal.getUserId());
        return ResponseEntity.ok(links == null ? List.of() : links);
    }

    /** Disconnect one provider for the caller; 404 when they had no such link. */
    @DeleteMapping("/{alias}")
    public ResponseEntity<Void> unlink(@AuthenticationPrincipal final UserCredentials principal,
                                       @PathVariable final String alias) {
        if (principal == null || principal.getUserId() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        final boolean removed = Boolean.TRUE.equals(
                publisher.unlink(new AccountUnlinkRef(principal.getUserId(), alias)));
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }
}
