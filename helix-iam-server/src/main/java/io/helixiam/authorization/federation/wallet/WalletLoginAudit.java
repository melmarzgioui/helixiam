/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Task 22: builds the {@code WALLET_LOGIN_SUCCESS} / {@code WALLET_LOGIN_FAILURE} AUTHN audit events. The detail is
 * always exactly {@code {transactionId, alias, format, issuerDn, result, reason}} (plus {@code invocation=dc_api} on a
 * failure of the W3C Digital Credentials API path) — a field that is not known at the
 * call site (e.g. {@code format}/{@code issuerDn} before a presentation was parsed, or {@code transactionId} before a
 * transaction was found) is left out, never a placeholder. Never includes a PID value, the subject hash, a nonce, a
 * code, the browser binding or {@code vp_token} content — callers must not pass any of those in.
 */
final class WalletLoginAudit {

    private static final String SUCCESS_TYPE = "WALLET_LOGIN_SUCCESS";
    private static final String FAILURE_TYPE = "WALLET_LOGIN_FAILURE";
    private static final String SUCCESS = "SUCCESS";
    private static final String FAILURE = "FAILURE";

    private WalletLoginAudit() {
    }

    /** A successful wallet login; {@code actor} is the resolved local user id (never a PID value). */
    static AuditEvent success(final String realm, final String actor, final String transactionId, final String alias,
            final String format, final String issuerDn) {
        return event(SUCCESS_TYPE, realm, actor, transactionId, alias, format, issuerDn, SUCCESS, null, null);
    }

    /** The {@code invocation} detail of a presentation that came through the W3C Digital Credentials API. */
    static final String DC_API = "dc_api";

    /** A rejected wallet login/presentation; {@code reason} is the {@link WalletErrorCode} behind it. */
    static AuditEvent failure(final String realm, final String transactionId, final String alias, final String format,
            final String issuerDn, final WalletErrorCode reason) {
        return failure(realm, transactionId, alias, format, issuerDn, reason, null);
    }

    /**
     * As {@link #failure(String, String, String, String, String, WalletErrorCode)}, adding {@code invocation} (e.g.
     * {@value #DC_API}) to the detail when it is not null.
     */
    static AuditEvent failure(final String realm, final String transactionId, final String alias, final String format,
            final String issuerDn, final WalletErrorCode reason, final String invocation) {
        return event(FAILURE_TYPE, realm, AuditContext.ANONYMOUS, transactionId, alias, format, issuerDn, FAILURE,
                reason == null ? null : reason.name(), invocation);
    }

    private static AuditEvent event(final String type, final String realm, final String actor,
            final String transactionId, final String alias, final String format, final String issuerDn,
            final String result, final String reason, final String invocation) {
        final Map<String, String> detail = new LinkedHashMap<>();
        put(detail, "transactionId", transactionId);
        put(detail, "alias", alias);
        put(detail, "format", format);
        put(detail, "issuerDn", issuerDn);
        put(detail, "result", result);
        put(detail, "reason", reason);
        put(detail, "invocation", invocation);
        return AuditEvent.authn(AuditContext.nowIso(), type, realm, actor, null, result, detail);
    }

    private static void put(final Map<String, String> detail, final String key, final String value) {
        if (value != null) {
            detail.put(key, value);
        }
    }
}
