/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.authz;

import java.util.List;

/** Helix IAM (Wave 6): the outcome of evaluating an authorization request. */
public record EvaluationResult(boolean granted, List<String> grantingPermissions, List<String> denyingPermissions) {
}
