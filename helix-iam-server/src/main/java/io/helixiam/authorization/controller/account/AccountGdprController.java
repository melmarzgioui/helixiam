package io.helixiam.authorization.controller.account;

import io.helixiam.authorization.amqp.gdpr.GdprConsentRecordDto;
import io.helixiam.authorization.amqp.gdpr.GdprConsentWithdrawDto;
import io.helixiam.authorization.amqp.gdpr.GdprExportDto;
import io.helixiam.authorization.amqp.gdpr.GdprPublisher;
import io.helixiam.authorization.amqp.gdpr.GdprUserRef;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Helix IAM (6) Self-service Account — GDPR/Privacy: the END-USER data-subject-rights API, served under
 * {@code /realms/{realm}/account/gdpr/**}. Every operation is keyed off the authenticated principal (never a
 * path/body userId), so a signed-in user can only export their own data, read their own consent ledger and
 * withdraw their own consents. Erasure is intentionally NOT exposed here — Art. 17 deletion stays an admin
 * action (a user cannot delete themselves through the account console). Returns {@link ResponseEntity}
 * throughout so a bad request never becomes a login redirect via {@code /error}.
 */
@RestController
@RequestMapping("/account/gdpr")
public class AccountGdprController {

    private final GdprPublisher publisher;

    public AccountGdprController(final GdprPublisher publisher) {
        this.publisher = publisher;
    }

    /** Art. 15/20: the signed-in user's own complete data export (secret-free). 401 when unauthenticated. */
    @GetMapping(value = "/export", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<GdprExportDto> export(@AuthenticationPrincipal final UserCredentials principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        final GdprExportDto export = publisher.export(new GdprUserRef(realm(), principal.getUserId()));
        return export == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(export);
    }

    /** Art. 7: the signed-in user's own consent ledger (grants + withdrawals). */
    @GetMapping("/consents")
    public ResponseEntity<List<GdprConsentRecordDto>> consents(@AuthenticationPrincipal final UserCredentials principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(publisher.listConsents(new GdprUserRef(realm(), principal.getUserId())));
    }

    /** Art. 7: withdraw the signed-in user's own consent for one client; 404 if there was no active consent. */
    @DeleteMapping("/consents/{clientId}")
    public ResponseEntity<Void> withdrawConsent(@AuthenticationPrincipal final UserCredentials principal,
                                                @PathVariable final String clientId) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        final boolean withdrawn = Boolean.TRUE.equals(
                publisher.withdrawConsent(new GdprConsentWithdrawDto(realm(), principal.getUserId(), clientId)));
        return withdrawn ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    private static String realm() {
        return RealmContextHolder.get();
    }
}
