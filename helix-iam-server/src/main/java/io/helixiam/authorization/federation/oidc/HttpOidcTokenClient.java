/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.oidc;

import io.helixiam.common.json.JsonMappers;
import io.helixiam.common.json.JsonNodes;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.net.PinnedHttpFetcher;
import io.helixiam.common.net.PinnedResourceRetriever;

import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
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

    /** Token endpoint: 5 s connect, 10 s in total, response body at most 1 MB. */
    static final PinnedHttpFetcher.Limits TOKEN_LIMITS = new PinnedHttpFetcher.Limits(Duration.ofSeconds(5),
            Duration.ofSeconds(10), 1024 * 1024);
    private final ObjectMapper objectMapper = JsonMappers.plain();
    /** M6: token endpoint and JWKS are fetched on the address the guard validated, without redirects. */
    private final PinnedHttpFetcher http;
    private final PinnedResourceRetriever jwksRetriever;
    private static final int MAX_JWK_SOURCES = 1_000;
    /** One JWK source per URL; the least recently used is dropped past {@value #MAX_JWK_SOURCES}. */
    private final io.helixiam.common.net.BoundedLruCache<String, JWKSource<SecurityContext>> jwkSources =
            new io.helixiam.common.net.BoundedLruCache<>(MAX_JWK_SOURCES);

    /** Secure default (block-private) — used by the non-Spring test/harness path. */
    public HttpOidcTokenClient() {
        this(new OutboundUrlGuard());
    }

    public HttpOidcTokenClient(final OutboundUrlGuard egressGuard) {
        this.http = PinnedHttpFetcher.plain(egressGuard,
                io.helixiam.common.net.FetchLimiter.Group.LOGIN_ADMIN, io.helixiam.authorization.security.realm.RealmContextHolder::get);
        this.jwksRetriever = new PinnedResourceRetriever(egressGuard,
                io.helixiam.common.net.FetchLimiter.Group.LOGIN_ADMIN, io.helixiam.authorization.security.realm.RealmContextHolder::get);
    }

    @Override
    public OidcTokens exchange(final OidcProviderConfig config, final String code, final String redirectUri) {
        final String form = "grant_type=authorization_code"
                + "&code=" + enc(code)
                + "&redirect_uri=" + enc(redirectUri)
                + "&client_id=" + enc(config.clientId())
                + "&client_secret=" + enc(config.clientSecret());
        try {
            // M6: the token endpoint comes from admin IdP config: one guarded resolution, a pinned connection
            final PinnedHttpFetcher.Response response = http.post(config.tokenEndpoint(), Map.of(
                    "Content-Type", "application/x-www-form-urlencoded", "Accept", "application/json"),
                    form.getBytes(StandardCharsets.UTF_8), TOKEN_LIMITS);
            if (response.status() != 200) {
                throw new IllegalStateException("OIDC token endpoint returned " + response.status()
                        + " for provider " + config.alias());
            }
            final JsonNode body = objectMapper.readTree(response.bodyAsString());
            final String idToken = JsonNodes.text(body.path("id_token"), null);
            if (idToken == null) {
                throw new IllegalStateException("OIDC token response has no id_token for provider " + config.alias());
            }
            return new OidcTokens(validateAndExtract(config, idToken), JsonNodes.text(body.path("access_token"), null));
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
        // M6: jwksUri comes from admin IdP config: fetched through the guard, pinned, without redirects
        // one cached source per jwks_uri (Nimbus caching: 5 minutes, refetch on an unknown kid, rate-limited)
        final java.net.URL jwksUrl = URI.create(config.jwksUri()).toURL();
        final JWKSource<SecurityContext> jwkSource = jwkSources.computeIfAbsent(config.jwksUri(),
                u -> JWKSourceBuilder.create(jwksUrl, jwksRetriever).build());

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
