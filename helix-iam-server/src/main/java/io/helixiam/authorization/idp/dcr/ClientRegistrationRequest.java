package io.helixiam.authorization.idp.dcr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Helix IAM E11 (RFC 7591): an OAuth2/OIDC Dynamic Client Registration request — the client metadata an
 * RP submits to {@code POST /connect/register}. Field names are the RFC 7591 snake_case wire names.
 * Unknown metadata is tolerated (the spec allows extension fields and SP-ignored fields).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientRegistrationRequest(
        @JsonProperty("redirect_uris") List<String> redirectUris,
        @JsonProperty("grant_types") List<String> grantTypes,
        @JsonProperty("response_types") List<String> responseTypes,
        @JsonProperty("token_endpoint_auth_method") String tokenEndpointAuthMethod,
        @JsonProperty("client_name") String clientName,
        @JsonProperty("scope") String scope,
        @JsonProperty("post_logout_redirect_uris") List<String> postLogoutRedirectUris,
        @JsonProperty("jwks_uri") String jwksUri,
        @JsonProperty("contacts") List<String> contacts) {
}
