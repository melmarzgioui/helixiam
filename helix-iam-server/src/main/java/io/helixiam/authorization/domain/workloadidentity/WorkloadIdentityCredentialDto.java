/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.workloadidentity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Subscriber-side copy of the WIF credential DTO carried over AMQP. The field ORDER must match the
 * publisher copy exactly (positional record over Jackson). {@link #from} maps the entity.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record WorkloadIdentityCredentialDto(String id, String realmId, String name, String issuer,
                                            String jwksUri, String subject, String audience, String clientId,
                                            String scopes, boolean enabled, Long createdAt) {

    public static WorkloadIdentityCredentialDto from(final WorkloadIdentityCredential c) {
        return new WorkloadIdentityCredentialDto(c.getId(), c.getRealmId(), c.getName(), c.getIssuer(),
                c.getJwksUri(), c.getSubject(), c.getAudience(), c.getClientId(), c.getScopes(), c.isEnabled(),
                c.getCreationDate() == null ? null : c.getCreationDate().getTime());
    }
}
