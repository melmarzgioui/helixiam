/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.clientauth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.common.net.FetchLimiter;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.net.PinnedResourceRetriever;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionDecoderFactory;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.Objects;

/**
 * The token endpoint's client-assertion decoder ({@code private_key_jwt}, {@code client_secret_jwt}). SAS's own
 * {@link JwtClientAssertionDecoderFactory} fetches a client's {@code jwk_set_url} with an unguarded RestTemplate that
 * follows redirects; that URL is chosen by whoever registers the client (open DCR included). Here a
 * {@code private_key_jwt} client's JWKS is fetched through {@link OutboundUrlGuard} on the pinned transport
 * ({@link PinnedResourceRetriever}: one guarded resolution, a connection to the validated address, no redirects, LOGIN
 * slots with a per-realm share), with Nimbus's caching: the key set is cached (5 minutes) and an unknown {@code kid}
 * triggers a rate-limited refetch, so a key rotation is picked up. {@code client_secret_jwt} (HMAC with the client
 * secret, no network) is delegated to SAS. Claim validation is SAS's ({@code DEFAULT_JWT_VALIDATOR_FACTORY}).
 */
public final class GuardedClientAssertionDecoderFactory implements JwtDecoderFactory<RegisteredClient> {

    private static final int MAX_DECODERS = 1_000;

    private final PinnedResourceRetriever retriever;
    private final JwtClientAssertionDecoderFactory macDecoders = new JwtClientAssertionDecoderFactory();
    /** Per client, URL and algorithm; the least recently used is dropped past {@value #MAX_DECODERS}. */
    private final io.helixiam.common.net.BoundedLruCache<String, JwtDecoder> decoders =
            new io.helixiam.common.net.BoundedLruCache<>(MAX_DECODERS);

    /** The field error for a JWKS URL, or null; by default the production {@code JwksUrlPolicy}. */
    private final java.util.function.Function<String, String> jwksUrlProblem;

    /** Production rules: the JWKS URL must be https. */
    public GuardedClientAssertionDecoderFactory(final OutboundUrlGuard guard) {
        this(guard, io.helixiam.common.startup.DeploymentProfile.production());
    }

    /** https, or http to localhost / 127.0.0.1 under the dev profile (the admin API's rule, at fetch time). */
    public GuardedClientAssertionDecoderFactory(final OutboundUrlGuard guard,
            final io.helixiam.common.startup.DeploymentProfile profile) {
        this(guard, url -> io.helixiam.authorization.service.client.JwksUrlPolicy.problem(url, profile.isDev()));
    }

    /** An explicit URL rule ({@code url -> null} accepts any scheme: tests that serve the JWKS over plain http). */
    public GuardedClientAssertionDecoderFactory(final OutboundUrlGuard guard,
            final java.util.function.Function<String, String> jwksUrlProblem) {
        this.retriever = new PinnedResourceRetriever(Objects.requireNonNull(guard, "guard"), FetchLimiter.Group.LOGIN_CLIENT,
                RealmContextHolder::get);
        this.jwksUrlProblem = Objects.requireNonNull(jwksUrlProblem, "jwksUrlProblem");
    }

    @Override
    public JwtDecoder createDecoder(final RegisteredClient client) {
        if (!(client.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm()
                instanceof SignatureAlgorithm alg)) {
            return macDecoders.createDecoder(client); // client_secret_jwt: the client secret, no fetch
        }
        final String jwkSetUrl = client.getClientSettings().getJwkSetUrl();
        if (jwkSetUrl == null || jwkSetUrl.isBlank()) {
            return refusing("The client has no registered JWK Set URL");
        }
        // a row stored before the https rule: fail closed, never fetch it
        if (jwksUrlProblem.apply(jwkSetUrl) != null) {
            return refusing("The client's JWK Set URL must be https");
        }
        final String key = client.getId() + "|" + jwkSetUrl + "|" + alg.getName();
        return decoders.computeIfAbsent(key, k -> build(client, jwkSetUrl, alg));
    }

    /**
     * A decoder that refuses every assertion. SAS only turns a {@link org.springframework.security.oauth2.jwt
     * .JwtException} from {@code decode} into {@code invalid_client}; one thrown by {@code createDecoder} is a 500.
     */
    private static JwtDecoder refusing(final String reason) {
        return token -> {
            throw new BadJwtException(reason);
        };
    }

    private JwtDecoder build(final RegisteredClient client, final String jwkSetUrl, final SignatureAlgorithm alg) {
        final JWKSource<SecurityContext> keys;
        try {
            keys = JWKSourceBuilder.create(URI.create(jwkSetUrl).toURL(), retriever).build();
        } catch (final MalformedURLException | IllegalArgumentException e) {
            throw new BadJwtException("The client's JWK Set URL is not a URL");
        }
        final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.parse(alg.getName()), keys));
        // typ: JWT, absent, or client-authentication+jwt (draft-ietf-oauth-rfc7523bis); anything else is refused
        processor.setJWSTypeVerifier(new com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier<>(
                com.nimbusds.jose.JOSEObjectType.JWT, null,
                new com.nimbusds.jose.JOSEObjectType("client-authentication+jwt")));
        processor.setJWTClaimsSetVerifier((claims, context) -> {
            // validated by SAS's validators below (aud, iss, sub, exp, nbf, jti)
        });
        final NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        decoder.setJwtValidator(JwtClientAssertionDecoderFactory.DEFAULT_JWT_VALIDATOR_FACTORY.apply(client));
        return decoder;
    }
}
