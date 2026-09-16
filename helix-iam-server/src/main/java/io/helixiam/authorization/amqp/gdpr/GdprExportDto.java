/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.gdpr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM GDPR Art. 15/20: the complete, machine-readable export of everything the platform holds about a
 * data subject (publisher-side copy; mirrors the subscriber's {@code domain.gdpr.GdprExportDto}). NEVER
 * carries secret material — credentials appear as metadata only.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GdprExportDto(Long generatedAt, String schema, String realmId, String userId,
                            GdprProfile profile, Map<String, String> attributes, List<String> roles,
                            List<GdprRealmMembership> realmMemberships, List<GdprOrgMembership> organizations,
                            List<GdprCredentialMeta> credentials, List<GdprFederatedLink> federatedLinks,
                            List<GdprConsentRecordDto> consents, List<GdprLoginEvent> loginEvents) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GdprProfile(String username, String email, boolean emailVerified, boolean enabled, boolean locked,
                              boolean mfaEnabled, Long createdAt) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GdprRealmMembership(String realmId, Long joinedAt) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GdprOrgMembership(String orgId, String name, String role) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GdprCredentialMeta(String type, String id, String label, String detail, Long createdAt,
                                     Long lastUsedAt) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GdprFederatedLink(String idpAlias, String externalSubject) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GdprLoginEvent(String type, String detail, Long at) {
    }
}
