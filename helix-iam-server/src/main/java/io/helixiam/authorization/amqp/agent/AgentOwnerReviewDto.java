/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.agent;

/**
 * One row of the owner-integrity review carried over the queue: an agent plus the verdict on its
 * {@code owner} ({@code VALID} / {@code UNKNOWN} / {@code ORPHANED}). Positional/field parity with the
 * subscriber's {@code domain.agent.AgentOwnerReviewDto}.
 */
public record AgentOwnerReviewDto(String id, String name, String owner, String status, String ownerStatus) {
}
