/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.client.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM E8.5-S3: create/update payload for an OAuth client (subscriber-side copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientWriteDto(String realmId, String id, String clientId, List<String> grantTypes,
                             List<String> redirectUris, List<String> scopes, String subjectClaim,
                             String authFlowAlias, String name, String description,
                             List<String> postLogoutRedirectUris, List<String> webOrigins,
                             Boolean publicClient, Boolean consentRequired, Boolean displayOnConsentScreen,
                             String loginTheme, String rootUrl, String homeUrl, String adminUrl,
                             Boolean alwaysDisplayInConsole,
                             Integer accessTokenLifespan, Integer refreshTokenLifespan, String idTokenSignatureAlg,
                             Boolean reuseRefreshTokens, String tokenEndpointAuthMethod, String jwksUrl,
                             String backchannelLogoutUri, String frontchannelLogoutUri, String applicationId,
                             Boolean x509CertificateBoundAccessTokens, Boolean requireSignedRequestObject,
                             String jarmResponseMode, String clientSecret) {

    /**
     * C2: every field but {@code clientSecret} — the caller-supplied secret is optional (null keeps the stored one
     * on update and generates one on create).
     */
    public ClientWriteDto(final String realmId, final String id, final String clientId, final List<String> grantTypes,
                          final List<String> redirectUris, final List<String> scopes, final String subjectClaim,
                          final String authFlowAlias, final String name, final String description,
                          final List<String> postLogoutRedirectUris, final List<String> webOrigins,
                          final Boolean publicClient, final Boolean consentRequired,
                          final Boolean displayOnConsentScreen, final String loginTheme, final String rootUrl,
                          final String homeUrl, final String adminUrl, final Boolean alwaysDisplayInConsole,
                          final Integer accessTokenLifespan, final Integer refreshTokenLifespan,
                          final String idTokenSignatureAlg, final Boolean reuseRefreshTokens,
                          final String tokenEndpointAuthMethod, final String jwksUrl,
                          final String backchannelLogoutUri, final String frontchannelLogoutUri,
                          final String applicationId, final Boolean x509CertificateBoundAccessTokens,
                          final Boolean requireSignedRequestObject, final String jarmResponseMode) {
        this(realmId, id, clientId, grantTypes, redirectUris, scopes, subjectClaim, authFlowAlias, name, description,
                postLogoutRedirectUris, webOrigins, publicClient, consentRequired, displayOnConsentScreen, loginTheme,
                rootUrl, homeUrl, adminUrl, alwaysDisplayInConsole, accessTokenLifespan, refreshTokenLifespan,
                idTokenSignatureAlg, reuseRefreshTokens, tokenEndpointAuthMethod, jwksUrl, backchannelLogoutUri,
                frontchannelLogoutUri, applicationId, x509CertificateBoundAccessTokens, requireSignedRequestObject,
                jarmResponseMode, null);
    }

    /** Never print the secret. */
    @Override
    public String toString() {
        return "ClientWriteDto[realmId=" + realmId + ", id=" + id + ", clientId=" + clientId
                + ", clientSecret=" + (clientSecret == null ? "null" : "***") + "]";
    }
}
