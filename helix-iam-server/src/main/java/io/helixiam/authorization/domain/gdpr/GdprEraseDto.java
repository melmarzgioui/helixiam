/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.gdpr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM GDPR Art. 17: erase or anonymize a data subject (subscriber-side copy).
 *
 * <p><b>mode</b> selects the erasure semantics:
 * <ul>
 *   <li>{@code "hard"} — physically delete the user: the global {@code user_credentials} row is removed and
 *       FK {@code ON DELETE CASCADE} drops attributes, tenant links, role assignments, org memberships,
 *       credentials, federated links and consent ledger. Nothing of the subject remains.</li>
 *   <li>{@code "anonymize"} (default) — keep the row for referential / audit integrity but overwrite every
 *       PII field with a tombstone (username → {@code anon-<id>}, email → null, attributes cleared,
 *       MFA secret cleared, account disabled + locked) and stamp {@code anonymized_at}. Memberships,
 *       credentials and consents are still cascaded/withdrawn so the subject can no longer authenticate.</li>
 * </ul>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GdprEraseDto(String realmId, String userId, String mode) {

    public static final String MODE_HARD = "hard";
    public static final String MODE_ANONYMIZE = "anonymize";

    /** Anonymize unless the caller explicitly asked for a hard delete. */
    public boolean isHardDelete() {
        return MODE_HARD.equalsIgnoreCase(mode);
    }
}
