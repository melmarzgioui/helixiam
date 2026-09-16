/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.exception;

import jakarta.validation.ConstraintViolation;

import java.util.Set;

/**
 * Vendored verbatim (package renamed only) from
 * io.helixiam.subscriber.starter.validation.exception.AbstractValidationException.
 * Not in the Task 1 file list; pulled in transitively because
 * io.helixiam.persistence.exception.DatabaseException needs a ValidationException base
 * (see VENDOR-MAP.md decisions).
 */
public interface AbstractValidationException {
    void handleViolation(final Set<ConstraintViolation<Object>> violations);
}
