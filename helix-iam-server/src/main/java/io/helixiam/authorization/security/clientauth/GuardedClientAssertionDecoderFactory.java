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
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

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
    private final Map<String, JwtDecoder> decoders = new ConcurrentHashMap<>();

    public GuardedClientAssertionDecoderFactory(final OutboundUrlGuard guard) {
        this.retriever = new PinnedResourceRetriever(Objects.requireNonNull(guard, "guard"), FetchLimiter.Group.LOGIN,
                RealmContextHolder::get);
    }

    @Override
    public JwtDecoder createDecoder(final RegisteredClient client) {
        if (!(client.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm()
                instanceof SignatureAlgorithm alg)) {
            return macDecoders.createDecoder(client); // client_secret_jwt: the client secret, no fetch
        }
        final String jwkSetUrl = client.getClientSettings().getJwkSetUrl();
        if (jwkSetUrl == null || jwkSetUrl.isBlank()) {
            throw new BadJwtException("The client has no registered JWK Set URL");
        }
        final String key = client.getId() + "|" + jwkSetUrl + "|" + alg.getName();
        if (decoders.size() >= MAX_DECODERS && !decoders.containsKey(key)) {
            decoders.clear();
        }
        return decoders.computeIfAbsent(key, k -> build(client, jwkSetUrl, alg));
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
        processor.setJWTClaimsSetVerifier((claims, context) -> {
            // validated by SAS's validators below (aud, iss, sub, exp, nbf, jti)
        });
        final NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        decoder.setJwtValidator(JwtClientAssertionDecoderFactory.DEFAULT_JWT_VALIDATOR_FACTORY.apply(client));
        return decoder;
    }
}
