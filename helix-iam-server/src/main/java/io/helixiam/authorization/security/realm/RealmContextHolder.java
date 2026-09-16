/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.realm;

/**
 * Helix IAM (multi-tenant): the realm of the in-flight HTTP request, derived from the {@code /realms/{realm}/…}
 * URL prefix by {@link RealmRoutingFilter} and read by the login flow, federation broker, client lookup and
 * key source (replacing the old hard-coded {@code "master"}). Bound per request thread, cleared in a finally.
 */
public final class RealmContextHolder {

    /** Request attribute mirror of the current realm (for code that has the request but not the thread). */
    public static final String ATTRIBUTE = "helix.realm";

    private static final ThreadLocal<String> REALM = new ThreadLocal<>();

    private RealmContextHolder() {
    }

    public static void set(final String realm) {
        REALM.set(realm);
    }

    /** The current realm, or {@code null} when outside a realm-routed request (e.g. {@code /admin/**}). */
    public static String get() {
        return REALM.get();
    }

    public static void clear() {
        REALM.remove();
    }
}
