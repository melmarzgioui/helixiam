package io.helixiam.authorization.controller.account;

import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.session.AccountSessionService;
import io.helixiam.authorization.session.AccountSessionService.AccountConsent;
import io.helixiam.authorization.session.SsoSessionView;
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
 * Helix IAM (6) Self-service Account: the END-USER Sessions + Consents API, served under
 * {@code /realms/{realm}/account/**}. Every operation is scoped to the authenticated principal via
 * {@link AccountSessionService}, so a user only ever sees and revokes their own sessions / application
 * consents. Returns {@link ResponseEntity} throughout (never throws) so the security chain can't turn a bad
 * request into a login redirect.
 */
@RestController
@RequestMapping("/account")
public class AccountSessionController {

    private final AccountSessionService service;

    public AccountSessionController(final AccountSessionService service) {
        this.service = service;
    }

    /** The caller's own active SSO sessions in this realm. */
    @GetMapping("/sessions")
    public ResponseEntity<List<SsoSessionView>> sessions(@AuthenticationPrincipal final UserCredentials principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(service.listSessions(realm(), principal.getUserId()));
    }

    /** Revoke one of the caller's own sessions (Single Logout); 404 if it is not theirs. */
    @DeleteMapping("/sessions/{ssoSessionId}")
    public ResponseEntity<Void> revokeSession(@AuthenticationPrincipal final UserCredentials principal,
                                              @PathVariable final String ssoSessionId) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return service.revokeSession(realm(), principal.getUserId(), ssoSessionId)
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /** The applications the caller has authorized (their consents). */
    @GetMapping("/consents")
    public ResponseEntity<List<AccountConsent>> consents(@AuthenticationPrincipal final UserCredentials principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(service.listConsents(realm(), principal.getUserId()));
    }

    /** Revoke the caller's consent for one application; 404 if they have no session for it. */
    @DeleteMapping("/consents/{clientId}")
    public ResponseEntity<Void> revokeConsent(@AuthenticationPrincipal final UserCredentials principal,
                                              @PathVariable final String clientId) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return service.revokeConsent(realm(), principal.getUserId(), clientId)
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    private static String realm() {
        return RealmContextHolder.get();
    }
}
