/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.authz;

import java.util.Set;

/** Helix IAM (Wave 6): the evaluator's view of a policy. {@code type}=ROLE; {@code logic}=POSITIVE|NEGATIVE. */
public record PolicyView(String name, String type, String logic, Set<String> roles) {
}
