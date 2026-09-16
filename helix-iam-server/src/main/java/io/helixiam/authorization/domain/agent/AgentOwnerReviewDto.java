/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.agent;

/**
 * One row of the owner-integrity review: an agent plus the verdict on its {@code owner}. {@code ownerStatus}
 * is one of {@code VALID} / {@code UNKNOWN} / {@code ORPHANED} (see
 * {@link io.helixiam.authorization.service.agent.OwnerIntegrity}).
 */
public record AgentOwnerReviewDto(String id, String name, String owner, String status, String ownerStatus) {
}
