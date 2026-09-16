/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.audit;

/**
 * Helix IAM B3: a paged, filtered query over the audit log. Null/blank filters are ignored. {@code page}
 * is zero-based; {@code size} is clamped by the service. Two-copy DTO (publisher mirror in amqp.audit).
 */
public record AuditQuery(String realm, String type, String actor, String outcome, String category,
                         int page, int size) {
}
