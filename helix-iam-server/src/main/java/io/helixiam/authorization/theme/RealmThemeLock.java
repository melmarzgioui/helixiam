/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

/**
 * Serialises theme writes and theme-asset writes of one realm for the rest of the current transaction (review M1).
 * Theme saves take it before validating, and asset uploads/deletions take it before their checks, so a theme can
 * never be validated against an asset that a concurrent, not yet committed deletion removes. Implemented by the
 * asset store ({@code theme.asset}); this interface keeps the {@code theme} package free of a dependency on it.
 */
public interface RealmThemeLock {

    /** No locking (no asset store present). */
    RealmThemeLock NONE = realmId -> { };

    /** Locks the realm until the current transaction ends. */
    void lockRealm(String realmId);
}
