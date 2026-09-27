/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * Helix IAM E8.5-S3: create/update request body for an OAuth client. C2: {@code clientSecret} is optional and
 * write-only — when set it becomes the client's secret (stored like a generated one); it is never returned.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientRequest(@NotBlank(message = "Client ID is required.") String clientId, List<String> grantTypes, List<String> redirectUris, List<String> scopes,
                            String subjectClaim, String authFlowAlias, String name, String description,
                            List<String> postLogoutRedirectUris, List<String> webOrigins,
                            Boolean publicClient, Boolean consentRequired, Boolean displayOnConsentScreen,
                            String loginTheme, String rootUrl, String homeUrl, String adminUrl,
                            Boolean alwaysDisplayInConsole,
                            Integer accessTokenLifespan, Integer refreshTokenLifespan, String idTokenSignatureAlg,
                            Boolean reuseRefreshTokens, String tokenEndpointAuthMethod, String jwksUrl,
                            String backchannelLogoutUri, String frontchannelLogoutUri, String applicationId,
                            Boolean x509CertificateBoundAccessTokens, Boolean requireSignedRequestObject,
                            String jarmResponseMode,
                            @Size(min = ClientSecretRequest.MIN_LENGTH, max = ClientSecretRequest.MAX_LENGTH,
                                    message = ClientSecretRequest.LENGTH_MESSAGE)
                            @Pattern(regexp = ClientSecretRequest.PATTERN,
                                    message = ClientSecretRequest.LENGTH_MESSAGE) String clientSecret) {

    /** Never print the secret. */
    @Override
    public String toString() {
        return "ClientRequest[clientId=" + clientId + ", clientSecret=" + (clientSecret == null ? "null" : "***") + "]";
    }
}
