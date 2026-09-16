/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.workloadidentity;

/**
 * Helix IAM WIF: the {@code (issuer, subject, audience)} triple extracted from a verified workload JWT,
 * scoped to a realm — sent to the subscriber to find the credential that authorizes the exchange.
 * SAME field order as the subscriber copy (positional record over Jackson).
 */
public record WorkloadIdentityResolveQuery(String realmId, String issuer, String subject, String audience) {
}
