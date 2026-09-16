package group.mfnr.authorization.idp.dcr;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Helix IAM E11 (RFC 7591 §3.2.1): the client information response — the registered metadata plus the
 * issued {@code client_id}/{@code client_secret} and the RFC 7592 management credentials
 * ({@code registration_access_token} + {@code registration_client_uri}).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ClientRegistrationResponse(
        @JsonProperty("client_id") String clientId,
        @JsonProperty("client_secret") String clientSecret,
        @JsonProperty("registration_access_token") String registrationAccessToken,
        @JsonProperty("registration_client_uri") String registrationClientUri,
        @JsonProperty("client_name") String clientName,
        @JsonProperty("redirect_uris") List<String> redirectUris,
        @JsonProperty("grant_types") List<String> grantTypes,
        @JsonProperty("response_types") List<String> responseTypes,
        @JsonProperty("token_endpoint_auth_method") String tokenEndpointAuthMethod,
        @JsonProperty("scope") String scope,
        @JsonProperty("post_logout_redirect_uris") List<String> postLogoutRedirectUris,
        @JsonProperty("jwks_uri") String jwksUri) {
}
