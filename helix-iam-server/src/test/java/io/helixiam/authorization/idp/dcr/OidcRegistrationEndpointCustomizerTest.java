package io.helixiam.authorization.idp.dcr;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E11 (RFC 7591): the OIDC discovery document advertises {@code registration_endpoint} under the
 * realm-prefixed issuer, so a relying party can auto-discover the Dynamic Client Registration endpoint.
 */
class OidcRegistrationEndpointCustomizerTest {

    private final OidcRegistrationEndpointCustomizer customizer = new OidcRegistrationEndpointCustomizer();

    @Test
    void advertisesRegistrationEndpointUnderTheRealmIssuer() {
        final OidcProviderConfiguration.Builder builder = OidcProviderConfiguration.builder()
                .issuer("https://idp.gov.nl/realms/gov")
                .authorizationEndpoint("https://idp.gov.nl/realms/gov/oauth2/authorize")
                .tokenEndpoint("https://idp.gov.nl/realms/gov/oauth2/token")
                .jwkSetUrl("https://idp.gov.nl/realms/gov/oauth2/jwks")
                .responseType("code")
                .subjectType("public")
                // SAS always populates this required claim before invoking the customizer; set it here so
                // the minimal test builder validates on build().
                .idTokenSigningAlgorithm("RS256");

        customizer.accept(builder);

        assertThat(builder.build().getClaimAsString("registration_endpoint"))
                .isEqualTo("https://idp.gov.nl/realms/gov/connect/register");
    }
}
