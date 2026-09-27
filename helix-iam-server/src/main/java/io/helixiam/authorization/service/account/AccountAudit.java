/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.account;

import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * B1: every change made in the account console is an audit event (category {@code AUTHN}, resource
 * {@code user/<userId>}, actor = the username), so it reaches the log, the SIEM webhook, the searchable audit store and
 * the realm's webhooks like sign-ins do. Event types: {@code ACCOUNT_PASSWORD_CHANGE}, {@code ACCOUNT_STEP_UP},
 * {@code ACCOUNT_TOTP_ENROL}, {@code ACCOUNT_TOTP_REMOVE}, {@code ACCOUNT_RECOVERY_CODES_REGENERATE},
 * {@code ACCOUNT_SESSIONS_SIGN_OUT_OTHERS}, {@code ACCOUNT_SESSION_SIGN_OUT}, {@code ACCOUNT_EMAIL_CHANGE},
 * {@code ACCOUNT_EMAIL_VERIFY},
 * {@code ACCOUNT_DATA_EXPORT} and {@code ACCOUNT_DELETE}; outcome {@code SUCCESS}, {@code FAILURE} or {@code DENIED}.
 * Secrets (passwords, codes, links) are never part of an event.
 */
@Component
public class AccountAudit {

    public static final String SUCCESS = "SUCCESS";
    public static final String FAILURE = "FAILURE";
    public static final String DENIED = "DENIED";

    private final AuditLog auditLog;

    public AccountAudit(final AuditLog auditLog) {
        this.auditLog = auditLog;
    }

    public void emit(final HttpServletRequest request, final String type, final String realm, final String username,
                     final String userId, final String outcome, final Map<String, String> detail) {
        auditLog.emit(new AuditEvent(AuditContext.nowIso(), AuditEvent.KIND, AuditEvent.AUTHN, type, realm,
                username == null ? AuditContext.ANONYMOUS : username, request == null ? null : AuditContext.clientIp(request),
                "user", userId, outcome, detail == null || detail.isEmpty() ? null : detail));
    }

    public void emit(final HttpServletRequest request, final String type, final String realm, final String username,
                     final String userId, final String outcome) {
        emit(request, type, realm, username, userId, outcome, null);
    }
}
