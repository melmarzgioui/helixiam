/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.messaging;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;

/** Helix IAM notifications (N2): a per-realm message template (publisher copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MessageTemplateDto(String id, String realmId,
                                 @NotBlank(message = "Template key is required.") String templateKey,
                                 @NotBlank(message = "Channel is required.") String channel,
                                 String subject, String body, boolean enabled, boolean html) {
}
