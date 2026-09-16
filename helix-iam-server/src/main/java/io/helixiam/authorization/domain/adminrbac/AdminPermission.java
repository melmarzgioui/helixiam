/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.adminrbac;

import java.util.Arrays;
import java.util.Optional;

/**
 * Helix IAM: the catalogue of fine-grained admin permissions (scopes) covering the console's
 * {@code /admin/**} resources — the Keycloak {@code realm-management} / WorkOS-class scoped-admin model.
 * <p>
 * An admin role (a realm role, {@code user_roles}) is mapped to a set of these via {@code admin_role_permission}.
 * {@link #REALM_ADMIN} is the super-permission: a role that holds it is granted everything.
 * <p>
 * Stored by {@link #name()} (the enum constant) in the grant table, so the wire/DB value is e.g.
 * {@code MANAGE_USERS}; {@link #key()} is the stable hyphenated form the console/API exchange.
 */
public enum AdminPermission {

    /** Full administrative control of the realm (super-permission — implies every other permission). */
    REALM_ADMIN("realm-admin", "Full realm administration"),

    VIEW_USERS("view-users", "View users"),
    MANAGE_USERS("manage-users", "Manage users"),
    VIEW_CLIENTS("view-clients", "View clients / applications"),
    MANAGE_CLIENTS("manage-clients", "Manage clients / applications"),
    MANAGE_ROLES("manage-roles", "Manage realm & client roles"),
    MANAGE_IDENTITY_PROVIDERS("manage-identity-providers", "Manage identity providers & federation"),
    MANAGE_AUTHORIZATION("manage-authorization", "Manage authorization (flows, scopes, claims, authz services)"),
    MANAGE_ORGANIZATIONS("manage-organizations", "Manage organizations & groups"),
    MANAGE_REALM("manage-realm", "Manage realm settings, notifications & provisioning"),
    VIEW_EVENTS("view-events", "View events & sessions"),
    MANAGE_EVENTS("manage-events", "Manage events config & revoke sessions");

    private final String key;
    private final String label;

    AdminPermission(final String key, final String label) {
        this.key = key;
        this.label = label;
    }

    /** Stable hyphenated identifier exchanged with the console/API (e.g. {@code manage-users}). */
    public String key() {
        return key;
    }

    /** Human-readable label for the console permission matrix. */
    public String label() {
        return label;
    }

    /** Resolves a permission from its {@link #key()} or enum {@link #name()} (case-insensitive); empty if unknown. */
    public static Optional<AdminPermission> from(final String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        final String v = value.trim();
        return Arrays.stream(values())
                .filter(p -> p.key.equalsIgnoreCase(v) || p.name().equalsIgnoreCase(v))
                .findFirst();
    }
}
