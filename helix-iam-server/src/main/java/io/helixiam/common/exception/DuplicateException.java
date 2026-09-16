/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.exception;

/**
 * Vendored verbatim (package renamed only) from
 * io.helixiam.subscriber.starter.validation.exception.DuplicateException.
 * Not in the Task 1 file list; pulled in transitively because
 * io.helixiam.persistence.exception.DatabaseExceptionHandler (on the Task 1 list) throws it.
 */
public class DuplicateException extends ValidationException {

    public DuplicateException(final String message) {
        super(message, 409);
    }

    public DuplicateException(final String field, final String message) {
        this("Duplicate value used");
        getValidation().put(field, message);
    }
}
