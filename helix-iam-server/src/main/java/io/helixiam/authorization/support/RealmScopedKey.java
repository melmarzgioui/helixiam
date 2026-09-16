/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.support;

/**
 * Helix IAM multi-tenant (MT-3): packs a realm together with a lookup key (client id / service-provider
 * id) into a single value. Originally formatted an AMQP request/reply payload so a serialized
 * single-argument queue could carry both realm and key; the transport is gone (Task 2, strip-RabbitMQ
 * migration) but the packed-key format itself is still used in-process (e.g. by the client-lookup path
 * that will be folded from the publisher in a later task), so this utility moved out of the (deleted)
 * {@code amqp} transport package into {@code support} rather than being deleted with it.
 *
 * <p>The separator is the ASCII Unit Separator ({@code U+001F}) — it cannot occur in a realm slug or an
 * OAuth client id / UUID, so the split is unambiguous. A payload with no separator is treated as the
 * admin realm {@code master} (defensive back-compat).
 */
public final class RealmScopedKey {

    /** ASCII Unit Separator — never present in a realm slug or client id/UUID. */
    public static final char SEPARATOR = '';

    /**
     * Sentinel client id returned over AMQP for a not-found (e.g. cross-realm) lookup instead of {@code null}.
     * A {@code null} reply on the serialized request/reply queue sends no message, so the publisher would block
     * for the full reply timeout; returning this sentinel lets the publisher resolve it to {@code null} at once.
     */
    public static final String NOT_FOUND_CLIENT_ID = "helix-not-found";

    private static final String DEFAULT_REALM = "master";

    private RealmScopedKey() {
    }

    /** {@code [realm, value]}. A payload without the separator yields {@code [master, payload]}. */
    public static String[] split(final String packed) {
        if (packed == null) {
            return new String[]{DEFAULT_REALM, null};
        }
        final int i = packed.indexOf(SEPARATOR);
        if (i < 0) {
            return new String[]{DEFAULT_REALM, packed};
        }
        return new String[]{packed.substring(0, i), packed.substring(i + 1)};
    }

    public static String pack(final String realm, final String value) {
        return (realm == null || realm.isBlank() ? DEFAULT_REALM : realm) + SEPARATOR + value;
    }
}
