/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.workloadidentity;

/** A realm-scoped reference to a WIF credential (for get/delete by id within a realm). */
public record WorkloadIdentityCredentialRef(String realmId, String id) {
}
