/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Reads a secret (or a CA bundle) from a mounted file, fresh at every call, so replacing the file (a rotated
 * Kubernetes secret) needs no restart. The value is trimmed; the file's path and contents are never logged.
 */
public final class SecretFiles {

    private static final Logger LOG = LogManager.getLogger(SecretFiles.class);
    private static final long MAX_BYTES = 1_048_576;

    private SecretFiles() {
    }

    /** The file's trimmed contents when {@code file} is set, else {@code value}; null when neither is usable. */
    public static String valueOrFile(final String value, final String file, final String what) {
        if (file != null && !file.isBlank()) {
            final String read = read(file, what);
            if (read != null) {
                return read;
            }
        }
        return value == null || value.isBlank() ? null : value;
    }

    /** The file's trimmed contents, or null (logged, without the path) when it cannot be read or is empty. */
    public static String read(final String file, final String what) {
        try {
            final Path path = Path.of(file.trim());
            if (Files.size(path) > MAX_BYTES) {
                LOG.warn("The {} file is larger than 1 MiB; ignored", what);
                return null;
            }
            final String text = Files.readString(path, StandardCharsets.UTF_8).trim();
            if (text.isEmpty()) {
                LOG.warn("The {} file is empty", what);
                return null;
            }
            return text;
        } catch (final IOException | RuntimeException e) {
            LOG.warn("The {} file cannot be read ({})", what, e.getClass().getSimpleName());
            return null;
        }
    }
}
