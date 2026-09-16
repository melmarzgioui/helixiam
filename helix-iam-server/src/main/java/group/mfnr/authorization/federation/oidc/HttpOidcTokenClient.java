package group.mfnr.authorization.federation.oidc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

/**
 * Helix IAM E5.2: live {@link OidcTokenClient} — exchanges the authorization code at the provider's
 * token endpoint over the TLS back-channel, then <b>fully validates the ID token</b> with Nimbus
 * before trusting any claim: RS256/ES256 signature against the provider's JWKS, the expected issuer
 * and audience (our client id), and expiry. A {@code @ConditionalOnMissingBean} so an alternative
 * client can replace it.
 */
public class HttpOidcTokenClient implements OidcTokenClient {

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public OidcTokens exchange(final OidcProviderConfig config, final String code, final String redirectUri) {
        final String form = "grant_type=authorization_code"
                + "&code=" + enc(code)
                + "&redirect_uri=" + enc(redirectUri)
                + "&client_id=" + enc(config.clientId())
                + "&client_secret=" + enc(config.clientSecret());
        try {
            final HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(config.tokenEndpoint()))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();
            final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("OIDC token endpoint returned " + response.statusCode()
                        + " for provider " + config.alias());
            }
            final JsonNode body = objectMapper.readTree(response.body());
            final String idToken = body.path("id_token").asText(null);
            if (idToken == null) {
                throw new IllegalStateException("OIDC token response has no id_token for provider " + config.alias());
            }
            return new OidcTokens(validateAndExtract(config, idToken), body.path("access_token").asText(null));
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted during OIDC token exchange", e);
        } catch (final IllegalStateException e) {
            throw e;
        } catch (final Exception e) {
            throw new IllegalStateException("OIDC token exchange failed for provider " + config.alias() + ": " + e.getMessage(), e);
        }
    }

    /** Verify the ID token signature (JWKS) + issuer + audience + expiry, and return its claims. */
    private Map<String, Object> validateAndExtract(final OidcProviderConfig config, final String idToken) throws Exception {
        if (config.jwksUri() == null || config.jwksUri().isBlank()) {
            throw new IllegalStateException("OIDC provider " + config.alias() + " has no jwksUri — cannot verify ID token");
        }
        final JWKSource<SecurityContext> jwkSource = JWKSourceBuilder
                .create(URI.create(config.jwksUri()).toURL()).build();

        final ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(
                Set.of(JWSAlgorithm.RS256, JWSAlgorithm.ES256), jwkSource));
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                config.clientId(),                                              // expected audience
                new JWTClaimsSet.Builder().issuer(config.issuer()).build(),     // exact-match issuer
                Set.of("sub", "exp")));                                         // required claims

        final JWTClaimsSet claims = processor.process(idToken, null);
        return claims.toJSONObject();
    }

    private static String enc(final String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }
}
