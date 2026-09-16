/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.saml;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM: the WSO2-class advanced SAML2 options for a relying party (service provider), carried as a
 * nested block on {@link SamlRelyingPartyConfig} so the core record stays small. All fields are nullable;
 * {@code null} means "use the IdP default" (applied publisher-side at assertion time), so an SP configured
 * before these options existed behaves exactly as before. Subscriber-side copy of the two-copy DTO.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SamlSpOptions(
        Boolean signAssertion,
        Boolean signResponse,
        Boolean wantAuthnRequestsSigned,
        Boolean wantLogoutRequestsSigned,
        Boolean encryptAssertion,
        String encryptionCertificate,
        String signatureAlgorithm,
        String digestAlgorithm,
        String nameIdFormat,
        Boolean includeAttributes,
        List<String> additionalAcsUrls,
        List<String> extraAudiences,
        List<String> extraRecipients,
        Boolean backChannelSloEnabled,
        Boolean idpInitiatedSsoEnabled,
        Integer assertionLifetimeSeconds) {
}
