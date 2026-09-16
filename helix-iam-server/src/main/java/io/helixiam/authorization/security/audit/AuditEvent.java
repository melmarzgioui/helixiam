/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.audit;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;

/**
 * Helix IAM E8.5-S4 (Events): one immutable, SIEM-shaped audit record. Serialized to a single flat JSON
 * line (emitted to stdout and optionally pushed to a SIEM webhook). Field order/names are the public
 * contract a SIEM parses, so keep them stable.
 *
 * @param ts           event time, UTC ISO-8601
 * @param kind         always {@code "audit"} — lets a SIEM filter audit lines from app logs
 * @param category     {@code AUTHN} or {@code ADMIN}
 * @param type         specific event type (e.g. {@code LOGIN_SUCCESS}, {@code CLIENT_SECRET_ROTATE})
 * @param realm        realm id, or {@code null} when not realm-scoped
 * @param actor        who caused it (username, {@code admin-api}, or {@code anonymous})
 * @param sourceIp     client IP (X-Forwarded-For first hop, else remote addr)
 * @param resourceType the kind of thing acted on (e.g. {@code user}, {@code client}), or {@code null}
 * @param resourceId   the id of that thing, or {@code null}
 * @param outcome      {@code SUCCESS}, {@code FAILURE} or {@code DENIED}
 * @param detail       optional extra context (reason, names), omitted from JSON when empty
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuditEvent(String ts, String kind, String category, String type, String realm, String actor,
                         String sourceIp, String resourceType, String resourceId, String outcome,
                         Map<String, String> detail) {

    public static final String KIND = "audit";
    public static final String AUTHN = "AUTHN";
    public static final String ADMIN = "ADMIN";

    /** An authentication event (login/logout); resource fields are unused. */
    public static AuditEvent authn(final String ts, final String type, final String realm, final String actor,
                                   final String sourceIp, final String outcome, final Map<String, String> detail) {
        return new AuditEvent(ts, KIND, AUTHN, type, realm, actor, sourceIp, null, null, outcome, emptyToNull(detail));
    }

    /** An admin mutation event derived from an {@code /admin/**} request. */
    public static AuditEvent admin(final String ts, final String type, final String realm, final String actor,
                                   final String sourceIp, final String resourceType, final String resourceId,
                                   final String outcome) {
        return new AuditEvent(ts, KIND, ADMIN, type, realm, actor, sourceIp, resourceType, resourceId, outcome, null);
    }

    private static Map<String, String> emptyToNull(final Map<String, String> detail) {
        return detail == null || detail.isEmpty() ? null : detail;
    }
}
