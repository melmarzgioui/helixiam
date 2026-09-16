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
                             String jarmResponseMode) {
}
