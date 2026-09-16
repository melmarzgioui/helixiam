/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.role;

/**
 * Helix IAM: the curated set of default (system) roles every realm is seeded with — the Keycloak/WSO2-class
 * out-of-the-box story. {@code admin} holds full realm administration, {@code user} is the default role every
 * new user receives, and {@code auditor} is a read-only admin. These names are stable and protected.
 */
public final class DefaultRoles {

    /** Full realm administrator — granted the {@code realm-admin} admin permission. */
    public static final String ADMIN = "admin";

    /** The realm's default role, auto-assigned to every new user. */
    public static final String USER = "user";

    /** Read-only administrator (view users / clients / events). */
    public static final String AUDITOR = "auditor";

    private DefaultRoles() {
    }
}
