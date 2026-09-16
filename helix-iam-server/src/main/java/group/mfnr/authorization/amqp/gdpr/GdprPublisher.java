package group.mfnr.authorization.amqp.gdpr;


import java.util.List;

/**
 * Helix IAM GDPR Art. 15/17/7: the data-subject-rights API's seam onto the user-domain store (owned by the
 * subscriber). JSON-marshalled two-copy DTOs, like the user-admin exchange.
 *
 * <p>Routing keys are FULLY DOT-delimited here (publisher convention); the subscriber's {@code @AnonymousListener}
 * keys are the same tokens dashed (e.g. {@code authorization.gdpr.export} ↔ {@code authorization-gdpr-export}).
 */
public interface GdprPublisher {

    String EXCHANGE_AUTHORIZATION_GDPR = "exchange-authorization-gdpr";
    String GDPR_EXPORT = "authorization.gdpr.export";
    String GDPR_ERASE = "authorization.gdpr.erase";
    String GDPR_CONSENTS_LIST = "authorization.gdpr.consents.list";
    String GDPR_CONSENT_RECORD = "authorization.gdpr.consent.record";
    String GDPR_CONSENT_WITHDRAW = "authorization.gdpr.consent.withdraw";

    /** Assemble the subject's full export, or {@code null} if they are not in the realm. */
    GdprExportDto export(final GdprUserRef ref);

    /** Erase or anonymize the subject. */
    GdprEraseResultDto erase(final GdprEraseDto erase);

    /** The subject's consent ledger (grants + withdrawals). */
    List<GdprConsentRecordDto> listConsents(final GdprUserRef ref);

    /** Record a consent grant; returns the persisted ledger row. */
    GdprConsentRecordDto recordConsent(final GdprConsentWriteDto write);

    /** Withdraw the subject's consent for one client; {@code false} if there was no active consent. */
    Boolean withdrawConsent(final GdprConsentWithdrawDto withdraw);
}
