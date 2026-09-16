/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.persistence.context;

import io.helixiam.persistence.config.DatabaseEnvironment;

public final class DatabaseContextHolder {

    private DatabaseContextHolder() {
        throw new IllegalAccessError();
    }

    private static final ThreadLocal<DatabaseEnvironment> CONTEXT = new ThreadLocal<>();

    public static void set(final DatabaseEnvironment databaseEnvironment) {
        CONTEXT.set(databaseEnvironment);
    }

    public static DatabaseEnvironment getEnvironment() {
        return CONTEXT.get();
    }

    public static void remove() {
        CONTEXT.remove();
    }

    public static void reset() {
        CONTEXT.set(DatabaseEnvironment.UPDATABLE);
    }
}
