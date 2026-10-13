/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.wallet.status.StatusPolicy;
import io.helixiam.authorization.federation.wallet.status.TokenStatusListClient;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.common.log.LogSafe;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * The audit of a wallet login that {@code FAIL_OPEN_WITH_AUDIT} let through without a revocation check
 * ({@code WALLET_STATUS_CHECK_FAILED}), with the wallet transaction it belongs to: the response handler runs a
 * presentation's verification {@link #duringTransaction inside its transaction}, and the status check's audit sink
 * ({@link #sink}) reads it on that thread. Without it the operator could tie a fail-open to its login only by time and
 * realm (final review m4).
 */
public final class WalletStatusAudit {

    private static final ThreadLocal<String> TRANSACTION = new ThreadLocal<>();

    private WalletStatusAudit() {
    }

    /** Runs {@code verification} with {@code transactionId} as this thread's wallet transaction, then forgets it. */
    public static <T> T duringTransaction(final String transactionId, final Supplier<T> verification) {
        final String previous = TRANSACTION.get();
        TRANSACTION.set(transactionId);
        try {
            return verification.get();
        } finally {
            if (previous == null) {
                TRANSACTION.remove();
            } else {
                TRANSACTION.set(previous);
            }
        }
    }

    /** This thread's wallet transaction, or {@code null} outside a verification. */
    public static String currentTransaction() {
        return TRANSACTION.get();
    }

    /** Emits {@code WALLET_STATUS_CHECK_FAILED} (AUTHN) for the current realm and the current wallet transaction. */
    public static TokenStatusListClient.AuditSink sink(final AuditLog auditLog) {
        Objects.requireNonNull(auditLog, "auditLog");
        return (host, code, detail) -> {
            final Map<String, String> details = new LinkedHashMap<>();
            details.put("reason", code.reason());
            details.put("statusListHost", LogSafe.sanitize(host));
            details.put("decision", StatusPolicy.OnUnavailable.FAIL_OPEN_WITH_AUDIT.name());
            final String transaction = TRANSACTION.get();
            if (transaction != null) {
                details.put("transactionId", transaction);
            }
            auditLog.emit(AuditEvent.authn(AuditContext.nowIso(), "WALLET_STATUS_CHECK_FAILED",
                    RealmContextHolder.get(), AuditContext.ANONYMOUS, null, "FAILURE", Map.copyOf(details)));
        };
    }
}
