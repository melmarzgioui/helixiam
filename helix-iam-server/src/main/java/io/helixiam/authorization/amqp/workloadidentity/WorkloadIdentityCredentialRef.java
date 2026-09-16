/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.workloadidentity;

/** Helix IAM WIF: realm-scoped reference to a federated credential (publisher copy). */
public record WorkloadIdentityCredentialRef(String realmId, String id) {
}
