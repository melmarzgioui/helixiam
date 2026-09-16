/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

/** Helix IAM SSO P5: deletes Spring Session (HTTP login session) rows, for cascading logout. */
public interface SpringSessionStore {

    /** Delete every HTTP session for this principal; returns the number removed (0 if none / in-memory). */
    int deleteByPrincipal(String principalName);
}
