/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.audit;

/**
 * Helix IAM B3: one persisted audit event, the over-the-queue shape (two-copy DTO; the publisher has a
 * mirror in {@code amqp.audit}). {@code detail} is a flattened JSON string of the event's detail map.
 */
public record AuditRecord(String ts, String kind, String category, String type, String realm, String actor,
                          String sourceIp, String resourceType, String resourceId, String outcome, String detail) {
}
