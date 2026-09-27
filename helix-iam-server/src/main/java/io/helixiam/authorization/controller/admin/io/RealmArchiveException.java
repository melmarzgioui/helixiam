/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin.io;

/** A realm archive is malformed, too large or inconsistent (the import answers 400 and imports nothing). */
public class RealmArchiveException extends RuntimeException {

    public RealmArchiveException(final String message) {
        super(message);
    }
}
