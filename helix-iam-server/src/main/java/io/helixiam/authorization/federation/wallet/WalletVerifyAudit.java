/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Verify-only mode (design D8): the {@code WALLET_VERIFY_SUCCESS} / {@code WALLET_VERIFY_FAILURE} AUTHN audit events of
 * the {@code eudi-wallet-verify} flow step. Same discipline as {@link WalletLoginAudit}: the detail is
 * {@code {transactionId, alias, format, issuerDn, result, reason, releasedClaims}}, unknown fields left out; released
 * claims by NAME only. Never a PID value, a subject hash, a nonce, a code or the binding.
 */
public final class WalletVerifyAudit {

    public static final String SUCCESS_TYPE = "WALLET_VERIFY_SUCCESS";
    public static final String FAILURE_TYPE = "WALLET_VERIFY_FAILURE";
    private static final String SUCCESS = "SUCCESS";
    private static final String FAILURE = "FAILURE";

    private WalletVerifyAudit() {
    }

    /** The step succeeded for {@code userId}; {@code releasedClaims} are the released claim names. */
    public static AuditEvent success(final String realm, final String userId, final String transactionId,
                                     final String alias, final String format, final String issuerDn,
                                     final Collection<String> releasedClaims) {
        final Map<String, String> detail = detail(transactionId, alias, format, issuerDn, SUCCESS, null);
        detail.put("releasedClaims", String.join(",", releasedClaims));
        return AuditEvent.authn(AuditContext.nowIso(), SUCCESS_TYPE, realm, userId, null, SUCCESS, detail);
    }

    /**
     * The verification was refused; {@code actor} is the identified user when known (the step), else anonymous (the
     * wallet's response endpoint has no session), and {@code reason} a {@link WalletErrorCode} name.
     */
    public static AuditEvent failure(final String realm, final String actor, final String transactionId,
                                     final String alias, final String format, final String issuerDn,
                                     final WalletErrorCode reason) {
        return AuditEvent.authn(AuditContext.nowIso(), FAILURE_TYPE, realm,
                actor == null ? AuditContext.ANONYMOUS : actor, null, FAILURE,
                detail(transactionId, alias, format, issuerDn, FAILURE, reason == null ? null : reason.name()));
    }

    private static Map<String, String> detail(final String transactionId, final String alias, final String format,
                                              final String issuerDn, final String result, final String reason) {
        final Map<String, String> detail = new LinkedHashMap<>();
        put(detail, "transactionId", transactionId);
        put(detail, "alias", alias);
        put(detail, "format", format);
        put(detail, "issuerDn", issuerDn);
        put(detail, "result", result);
        put(detail, "reason", reason);
        return detail;
    }

    private static void put(final Map<String, String> detail, final String key, final String value) {
        if (value != null) {
            detail.put(key, value);
        }
    }
}
