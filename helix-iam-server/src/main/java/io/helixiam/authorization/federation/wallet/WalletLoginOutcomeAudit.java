/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.FederatedLoginOutcome;
import io.helixiam.authorization.security.audit.AuditLog;
import org.springframework.stereotype.Component;

import java.io.Serializable;

/**
 * Final review F2: audits a wallet login that had to wait for a post-broker step-up (or MFA enrolment) when it ends:
 * {@code WALLET_LOGIN_SUCCESS} naming the user it signed in, or {@code WALLET_LOGIN_FAILURE} when it ended without a
 * session. {@link WalletLoginCompleter} hands the {@link Marker} over with the login; one event per transaction, like
 * a login that completes at once.
 *
 * <p>A step-up the user walks away from is not audited: nothing on the server marks that moment (the session just
 * expires, and expiry is not observed on every session store), and a wrong second-factor code is a retry, not an end.
 * Such a transaction has no {@code WALLET_LOGIN_*} event.
 */
@Component
public class WalletLoginOutcomeAudit implements FederatedLoginOutcome {

    private final AuditLog audit;

    public WalletLoginOutcomeAudit(final AuditLog audit) {
        this.audit = audit;
    }

    /**
     * What the audit event of a pending wallet login carries: the same non-PII fields as an immediate one (realm,
     * transaction id, alias, credential format, issuer DN).
     */
    public record Marker(String realm, String transactionId, String alias, String format, String issuerDn)
            implements Serializable {
    }

    @Override
    public boolean supports(final Serializable marker) {
        return marker instanceof Marker;
    }

    @Override
    public void completed(final Serializable marker, final String userId) {
        if (marker instanceof Marker m) {
            audit.emit(WalletLoginAudit.success(m.realm(), userId, m.transactionId(), m.alias(), m.format(),
                    m.issuerDn()));
        }
    }

    @Override
    public void failed(final Serializable marker) {
        if (marker instanceof Marker m) {
            audit.emit(WalletLoginAudit.failure(m.realm(), m.transactionId(), m.alias(), m.format(), m.issuerDn(),
                    WalletErrorCode.INVALID_RESPONSE));
        }
    }
}
