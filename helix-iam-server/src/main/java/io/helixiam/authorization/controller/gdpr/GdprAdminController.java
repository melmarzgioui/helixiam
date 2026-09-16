package io.helixiam.authorization.controller.gdpr;

import io.helixiam.authorization.amqp.gdpr.GdprConsentRecordDto;
import io.helixiam.authorization.amqp.gdpr.GdprEraseDto;
import io.helixiam.authorization.amqp.gdpr.GdprEraseResultDto;
import io.helixiam.authorization.amqp.gdpr.GdprExportDto;
import io.helixiam.authorization.amqp.gdpr.GdprPublisher;
import io.helixiam.authorization.amqp.gdpr.GdprUserRef;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Helix IAM GDPR Art. 15/17/7: the admin-console data-subject-rights API. Lets a realm admin export a
 * user's full data (Art. 15/20), erase or anonymize them (Art. 17) and read their consent ledger (Art. 7).
 * Realm + userId come from the path so a subject can only be addressed within their realm. Returns
 * {@link ResponseEntity} throughout (never throws) so a bad request is a clean 4xx, not a {@code /error}
 * → login redirect.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/users/{userId}/gdpr")
public class GdprAdminController {

    private final GdprPublisher publisher;

    public GdprAdminController(final GdprPublisher publisher) {
        this.publisher = publisher;
    }

    /** Art. 15/20: the subject's complete data export (secret-free). 404 if not a member of the realm. */
    @GetMapping(value = "/export", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<GdprExportDto> export(@PathVariable final String realmId,
                                                @PathVariable final String userId) {
        final GdprExportDto export = publisher.export(new GdprUserRef(realmId, userId));
        return export == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(export);
    }

    /**
     * Art. 17: erase or anonymize the subject. {@code mode} = {@code "anonymize"} (default) or {@code "hard"}.
     * 404 when the subject was not in the realm.
     */
    @DeleteMapping
    public ResponseEntity<GdprEraseResultDto> erase(@PathVariable final String realmId,
                                                    @PathVariable final String userId,
                                                    @RequestParam(name = "mode", defaultValue = "anonymize") final String mode) {
        final GdprEraseResultDto result = publisher.erase(new GdprEraseDto(realmId, userId, mode));
        if (result == null || !result.found()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(result);
    }

    /** Art. 7: the subject's consent ledger (grants + withdrawals), newest grant first. */
    @GetMapping("/consents")
    public ResponseEntity<List<GdprConsentRecordDto>> consents(@PathVariable final String realmId,
                                                               @PathVariable final String userId) {
        return ResponseEntity.ok(publisher.listConsents(new GdprUserRef(realmId, userId)));
    }
}
