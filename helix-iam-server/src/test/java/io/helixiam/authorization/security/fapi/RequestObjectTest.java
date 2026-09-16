package io.helixiam.authorization.security.fapi;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM B11 (FAPI / RFC 9101 — JWT-Secured Authorization Request, "JAR"): the {@code request}
 * parameter is a JWT whose claims ARE the authorization request parameters. {@link RequestObject} extracts
 * those OAuth parameters from the verified JWT (dropping the JWT-registered claims) so the authorization
 * endpoint can use the request-object values. Signature verification + the servlet wiring are glue around
 * this pure projection.
 */
class RequestObjectTest {

    @Test
    void extractsOAuthParametersAndDropsRegisteredJwtClaims() throws Exception {
        final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("web-app")
                .audience("https://iam.example/realms/master")
                .expirationTime(new java.util.Date())
                .issueTime(new java.util.Date())
                .jwtID("nonce-jti")
                .claim("response_type", "code")
                .claim("client_id", "web-app")
                .claim("redirect_uri", "https://app/cb")
                .claim("scope", "openid profile")
                .claim("state", "abc")
                .claim("nonce", "n-0S6")
                .build();

        final Map<String, String> params = RequestObject.toParameters(claims);

        assertThat(params)
                .containsEntry("response_type", "code")
                .containsEntry("client_id", "web-app")
                .containsEntry("redirect_uri", "https://app/cb")
                .containsEntry("scope", "openid profile")
                .containsEntry("state", "abc")
                .containsEntry("nonce", "n-0S6");
        // iss/aud/exp/iat/jti are JWT-registered, not OAuth request parameters
        assertThat(params).doesNotContainKeys("iss", "aud", "exp", "iat", "jti");
    }

    @Test
    void emptyForNullClaims() {
        assertThat(RequestObject.toParameters(null)).isEmpty();
    }
}
