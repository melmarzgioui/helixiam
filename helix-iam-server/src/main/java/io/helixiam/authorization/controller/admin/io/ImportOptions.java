package io.helixiam.authorization.controller.admin.io;

import java.util.Locale;

/**
 * Helix IAM: how a realm import treats entries that already exist, and how it resolves secret placeholders.
 *
 * <ul>
 *   <li>{@link OnConflict#OVERWRITE} — upsert: existing entries are updated (the historical behaviour).</li>
 *   <li>{@link OnConflict#SKIP} — block: existing entries are left untouched (only new ones are created).</li>
 *   <li>{@link OnConflict#FAIL} — block and report: like SKIP, but each conflict is recorded in the result
 *       so the caller can surface / reject it.</li>
 * </ul>
 *
 * @param onConflict          what to do when an entry's natural key already exists in the target realm
 * @param missingSecretPolicy what to do when a {@code ${ENV_VAR}} secret placeholder has no environment value
 */
public record ImportOptions(OnConflict onConflict, SecretPlaceholders.MissingPolicy missingSecretPolicy) {

    /** Conflict-resolution strategy for entries whose natural key already exists. */
    public enum OnConflict {
        OVERWRITE, SKIP, FAIL
    }

    /** Default options: upsert, and leave a secret unset when its env var is absent. */
    public static final ImportOptions OVERWRITE =
            new ImportOptions(OnConflict.OVERWRITE, SecretPlaceholders.MissingPolicy.LEAVE_UNSET);

    public ImportOptions {
        if (onConflict == null) {
            onConflict = OnConflict.OVERWRITE;
        }
        if (missingSecretPolicy == null) {
            missingSecretPolicy = SecretPlaceholders.MissingPolicy.LEAVE_UNSET;
        }
    }

    /** Convenience for tests/callers that only care about the conflict mode. */
    public ImportOptions(final OnConflict onConflict) {
        this(onConflict, SecretPlaceholders.MissingPolicy.LEAVE_UNSET);
    }

    /** Parses a request/env string ({@code overwrite|skip|fail}, case-insensitive) → defaults to OVERWRITE. */
    public static OnConflict conflictOf(final String raw) {
        if (raw == null || raw.isBlank()) {
            return OnConflict.OVERWRITE;
        }
        try {
            return OnConflict.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (final IllegalArgumentException ex) {
            return OnConflict.OVERWRITE;
        }
    }
}
