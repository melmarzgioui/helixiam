/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.workloadidentity;

/**
 * The {@code (issuer, subject, audience)} triple extracted from a verified workload JWT, scoped to a
 * realm — carried over AMQP so the subscriber can find the credential that authorizes the exchange.
 * Field order must match the publisher copy (positional record over Jackson).
 */
public record WorkloadIdentityResolveQuery(String realmId, String issuer, String subject, String audience) {
}
