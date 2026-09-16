/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.audit;

import java.util.ArrayList;
import java.util.List;

/**
 * Helix IAM E8.5-S4 (Events): a sanitized, read-only view of the audit/SIEM configuration for the
 * console's Events screen. The secret auth header is NEVER included — only whether one is configured.
 */
public record AuditConfigDto(boolean enabled, List<String> transports, String httpUrl, boolean httpConfigured,
                             boolean authConfigured, List<String> categories, int timeoutMs) {

    /** Builds the sanitized view from the live properties. */
    public static AuditConfigDto from(final HelixAuditProperties props) {
        final List<String> transports = new ArrayList<>();
        transports.add("stdout");
        if (props.httpConfigured()) {
            transports.add("http");
        }
        return new AuditConfigDto(
                props.isEnabled(),
                transports,
                props.getHttp().getUrl(),
                props.httpConfigured(),
                props.getHttp().authConfigured(),
                props.getCategories(),
                props.getHttp().getTimeoutMs());
    }
}
