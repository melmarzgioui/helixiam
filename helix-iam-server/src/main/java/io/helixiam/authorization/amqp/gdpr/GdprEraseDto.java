/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.gdpr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM GDPR Art. 17: erase or anonymize a data subject (publisher-side copy). {@code mode} is
 * {@code "hard"} (physical delete + FK cascade) or {@code "anonymize"} (tombstone PII, keep the row).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GdprEraseDto(String realmId, String userId, String mode) {
}
