package io.helixiam.authorization.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A machine (client_credentials) token must carry the REALM issuer — the same issuer the AS advertises in
 * discovery — so any standards-compliant resource server (e.g. an MCP server, RFC 9068) can validate it.
 * Historically Helix stamped {@code iss = client_id} here, which no external RS can verify. The customizer
 * still pins {@code sub}/{@code aud} to the client id (the delegation flow relies on {@code sub}), but must
 * NOT touch the issuer the token generator already set.
 */
class MachineTokenCustomizerTest {

    private static final String REALM_ISSUER = "http://localhost:8183/realms/master";

    private static RegisteredClient client() {
        return RegisteredClient.withId("id")
                .clientId("svc-client")
                .clientSecret("{noop}secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("read")
                .build();
    }

    /** A freshly-generated client_credentials token: SAS has already set iss = realm issuer. */
    private static JwtEncodingContext freshContext() {
        return JwtEncodingContext.with(JwsHeader.with(() -> "RS256"),
                        JwtClaimsSet.builder()
                                .issuer(REALM_ISSUER)             // SAS default: realm issuer
                                .subject("principal-name")
                                .issuedAt(Instant.now())
                                .expiresAt(Instant.now().plusSeconds(3600)))
                .registeredClient(client())
                .principal(new UsernamePasswordAuthenticationToken("svc-client", null))
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();
    }

    @Test
    void keepsRealmIssuerAndDoesNotStampClientId() {
        final JwtEncodingContext ctx = freshContext();

        MachineTokenCustomizer.applyMachineTokenIdentity(ctx);

        final JwtClaimsSet claims = ctx.getClaims().build();
        assertThat(claims.getClaim("iss").toString()).isEqualTo(REALM_ISSUER);
        assertThat(claims.getClaim("iss").toString()).isNotEqualTo("svc-client");
    }

    @Test
    void pinsSubjectAndAudienceToClientId() {
        final JwtEncodingContext ctx = freshContext();

        MachineTokenCustomizer.applyMachineTokenIdentity(ctx);

        final JwtClaimsSet claims = ctx.getClaims().build();
        assertThat(claims.getSubject()).isEqualTo("svc-client");
        assertThat(claims.getAudience()).containsExactly("svc-client");
    }
}
