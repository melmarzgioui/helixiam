/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.scim;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM B7: subscriber-side two-copy DTO for an outbound SCIM provisioning target (mirrors the
 * publisher's {@code amqp.scim.ScimTargetDto}). Carries the bearer {@code token} over the internal AMQP
 * seam so the publisher's dispatcher can authenticate to the service provider; the console-facing
 * controller strips it on read. {@code tokenSet} tells the console whether a token exists without revealing it.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScimTargetDto(String id, String realmId, String name, String baseUrl, String token,
                            boolean tokenSet, String eventTypes, boolean enabled, Long createdAt) {

    public static ScimTargetDto from(final ScimTarget t) {
        return new ScimTargetDto(t.getId(), t.getRealmId(), t.getName(), t.getBaseUrl(), t.getToken(),
                t.getToken() != null && !t.getToken().isBlank(), t.getEventTypes() == null ? "" : t.getEventTypes(),
                t.isEnabled(), t.getCreationDate() == null ? null : t.getCreationDate().getTime());
    }
}
