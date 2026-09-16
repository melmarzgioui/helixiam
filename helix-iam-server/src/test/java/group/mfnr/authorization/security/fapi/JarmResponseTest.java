package group.mfnr.authorization.security.fapi;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM B11 (FAPI / JARM — JWT-secured Authorization Response Mode): the authorization response
 * parameters (code, state, iss, or error) are returned inside a signed JWT instead of plain query/fragment
 * values. {@link JarmResponse} is the pure core: it resolves the delivery mode and builds the response
 * JWT's claim set (iss/aud/exp + the response params). Signing + the redirect are thin glue around it.
 */
class JarmResponseTest {

    @Test
    void resolvesTheDeliveryModeFromTheJarmResponseMode() {
        // "jwt" defaults to query for an authorization-code response; explicit variants pick their base mode.
        assertThat(JarmResponse.baseMode("jwt")).isEqualTo("query");
        assertThat(JarmResponse.baseMode("query.jwt")).isEqualTo("query");
        assertThat(JarmResponse.baseMode("fragment.jwt")).isEqualTo("fragment");
        assertThat(JarmResponse.baseMode("form_post.jwt")).isEqualTo("form_post");
    }

    @Test
    void recognisesOnlyJwtSecuredModes() {
        assertThat(JarmResponse.isJarm("jwt")).isTrue();
        assertThat(JarmResponse.isJarm("query.jwt")).isTrue();
        assertThat(JarmResponse.isJarm("fragment.jwt")).isTrue();
        assertThat(JarmResponse.isJarm("form_post.jwt")).isTrue();
        assertThat(JarmResponse.isJarm("query")).isFalse();
        assertThat(JarmResponse.isJarm(null)).isFalse();
        assertThat(JarmResponse.isJarm("")).isFalse();
    }

    @Test
    void buildsAResponseJwtWithIssuerAudienceExpiryAndAllResponseParameters() {
        final Instant now = Instant.parse("2026-06-29T12:00:00Z");
        final Map<String, String> params = new LinkedHashMap<>();
        params.put("code", "AUTH-CODE-123");
        params.put("state", "xyz");

        final JWTClaimsSet claims = JarmResponse.claims("https://iam.example/realms/master", "web-app", params, now, 120);

        assertThat(claims.getIssuer()).isEqualTo("https://iam.example/realms/master");
        assertThat(claims.getAudience()).containsExactly("web-app");
        assertThat(claims.getExpirationTime().toInstant()).isEqualTo(now.plusSeconds(120));
        assertThat(claims.getClaim("code")).isEqualTo("AUTH-CODE-123");
        assertThat(claims.getClaim("state")).isEqualTo("xyz");
    }
}
