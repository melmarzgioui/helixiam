/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.helixiam.authorization.federation.wallet.dcql.DcqlQueryBuilder;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction.Flow;
import io.helixiam.authorization.service.key.SigningKeyHandle;
import org.springframework.web.util.UriUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Builds what the verifier hands a wallet (docs/eudi-wallet-spec-notes.md §1.1–§1.3, §1.10, §2; quick reference §8):
 * the signed request object (JAR, served at the {@code request_uri}), the {@code client_id} and the invocation URL.
 *
 * <h2>Request object</h2>
 * Header: {@code typ=oauth-authz-req+jwt}, {@code alg} from the key ({@link SigningKeyHandle#algorithm()}), {@code x5c}
 * = {@link SigningKeyHandle#certificateChain()} (leaf first, no root; standard base64 DER per RFC 7515 §4.1.6). It is
 * signed through {@link SigningKeyHandle#signer()}; the private key is never touched here. A dev-PEM provider must be
 * given a handle whose chain is its configured {@code accessCertificateChain}; the config was already validated by
 * {@link WalletConfigValidator}, so nothing is re-validated here.
 *
 * <p>Claims: {@code response_type=vp_token}, {@code client_id}, {@code response_mode}, {@code response_uri},
 * {@code nonce}, {@code state} ({@link #walletState}, never {@code helixState}), {@code dcql_query} (the transaction's
 * query as a JSON object), {@code client_metadata}, {@code aud=https://self-issued.me/v2} (§5.8, static discovery),
 * {@code iat} = the transaction's creation and {@code exp} = its expiry (both rounded down to whole seconds; neither
 * depends on when the request is fetched, so a wallet that fetches it again, conformance ruling D2, gets the same claims
 * unless an admin edited the provider in between: {@code response_mode} and {@code client_metadata} are read from the
 * live config; a POST fetch's {@code wallet_nonce} and the ECDSA signature always differ). OpenID4VP defines neither
 * {@code iat} nor {@code exp} for the request object; JAR allows them. {@code nbf} and {@code iss} are left out:
 * neither OpenID4VP nor HAIP asks for them, and wallets ignore {@code iss} (§5).
 *
 * <p>{@code client_metadata}: {@code vp_formats_supported} for the configured formats (notes §1.3, the COSE ids
 * without HMAC and without {@code -50}); for {@code direct_post.jwt} also {@code jwks} holding only the public part of
 * the transaction's ephemeral P-256 key ({@code use=enc}, {@code alg=ECDH-ES}, its {@code kid}) and
 * {@code encrypted_response_enc_values_supported} = {@link #RESPONSE_ENC_VALUES} (HAIP §5: Verifiers MUST list both).
 * For the dev-only {@code direct_post} both are left out, since the response is not encrypted (§5.1: the enc list
 * "SHOULD be absent" then) and an advertised key would change the mdoc handover's {@code jwk_thumbprint}.
 *
 * <h2>URLs</h2>
 * The wallet endpoints are realm scoped like the other federation routes
 * ({@code idpBaseUrl + "/realms/" + realm + "/broker/" + alias + "/callback"}):
 * {@code <base>/realms/<realm>/oid4vp/<alias>/request/<requestId>} ({@link #requestUri}) and
 * {@code <base>/realms/<realm>/oid4vp/<alias>/response/<responseId>} ({@link #responseUri}); {@code base} is the
 * public server origin ({@code idpBaseUrl}), each path segment percent-encoded; a base that is not a URI or has no
 * host is an {@link IllegalStateException} with its own message. The invocation URL is
 * {@code <scheme>://?client_id=<pct>&request_uri=<pct>} with RFC 3986 percent-encoding (only unreserved characters
 * stay literal; never form encoding). {@code request_uri_method} is added only when the provider asks for
 * {@code post}: GET is the RFC 9101 default when it is absent, and HAIP does not require it (notes §2.4).
 */
public final class AuthorizationRequestFactory {

    /** OpenID4VP 1.0 §5. */
    public static final String REQUEST_OBJECT_TYP = "oauth-authz-req+jwt";
    /** OpenID4VP 1.0 §5.8, static discovery. */
    public static final String AUDIENCE = "https://self-issued.me/v2";
    /**
     * {@code encrypted_response_enc_values_supported}; HAIP §5 requires Verifiers to support and list both. Pass the
     * same set to {@link VpResponseDecryptor#decrypt}.
     */
    public static final Set<EncryptionMethod> RESPONSE_ENC_VALUES = Collections.unmodifiableSet(
            new LinkedHashSet<>(List.of(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM)));

    private static final String X509_HASH = "x509_hash:";
    private static final String X509_SAN_DNS = "x509_san_dns:";
    private static final List<String> JOSE_ALGS = List.of("ES256", "ES384", "ES512");
    /** COSE ES256, ESP256, ES384, ESP384, ES512, ESP512 (notes §1.3; no HMAC ids, no -50). */
    private static final List<Integer> COSE_ALGS = List.of(-7, -9, -35, -51, -36, -52);

    private final Clock clock;

    public AuthorizationRequestFactory() {
        this(Clock.systemUTC());
    }

    public AuthorizationRequestFactory(final Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    // ------------------------------------------------------------------------------------------------ client_id

    /**
     * The full {@code client_id} including its prefix (OpenID4VP §5.9.3): {@code x509_hash:} + unpadded base64url
     * SHA-256 of the DER of the leaf ({@code key.certificateChain().get(0)}), or {@code x509_san_dns:} +
     * {@code clientIdHost}. The certificate comes from the key because the hash binds the request to the certificate
     * that signs it.
     */
    public static String clientId(final WalletProviderConfig cfg, final SigningKeyHandle key) {
        return switch (cfg.clientIdScheme()) {
            case X509_HASH -> X509_HASH + base64Url(sha256(der(leaf(key))));
            case X509_SAN_DNS -> X509_SAN_DNS + Objects.requireNonNull(cfg.clientIdHost(), "clientIdHost").trim();
        };
    }

    /**
     * The request-object {@code state}: unpadded base64url SHA-256 of the transaction id. Deterministic so the
     * response handler can recompute it; it never carries {@code helixState}, which must not reach the wallet.
     */
    public static String walletState(final String transactionId) {
        return base64Url(sha256(Objects.requireNonNull(transactionId, "transactionId")
                .getBytes(StandardCharsets.UTF_8)));
    }

    // ------------------------------------------------------------------------------------------------ URLs

    /** {@code <base>/realms/<realm>/oid4vp/<alias>/request/<the flow's request id>}. */
    public static String requestUri(final String base, final WalletTransaction tx, final Flow flow) {
        final String requestId = switch (Objects.requireNonNull(flow, "flow")) {
            case SAME_DEVICE -> tx.sameDeviceRequestId();
            case CROSS_DEVICE -> tx.crossDeviceRequestId();
        };
        return endpoint(base, tx, "request", requestId);
    }

    /** {@code <base>/realms/<realm>/oid4vp/<alias>/response/<responseId>} (the {@code response_uri}). */
    public static String responseUri(final String base, final WalletTransaction tx) {
        return endpoint(base, tx, "response", tx.responseId());
    }

    private static String endpoint(final String base, final WalletTransaction tx, final String kind,
            final String id) {
        return origin(base) + "/realms/" + pct(tx.realmId()) + "/oid4vp/" + pct(tx.providerAlias()) + "/" + kind + "/"
                + pct(Objects.requireNonNull(id, kind + " id"));
    }

    /**
     * {@code <scheme>://?client_id=...&request_uri=...} for {@code flow}, plus {@code request_uri_method=post} when
     * configured (see the class comment).
     */
    public String invocationUrl(final WalletTransaction tx, final WalletProviderConfig cfg, final SigningKeyHandle key,
            final Flow flow, final String requestUriBase) {
        final StringBuilder url = new StringBuilder(cfg.invocationScheme()).append("://?client_id=")
                .append(pct(clientId(cfg, key))).append("&request_uri=")
                .append(pct(requestUri(requestUriBase, tx, flow)));
        if (cfg.requestUriMethod() == WalletProviderConfig.RequestUriMethod.POST) {
            url.append("&request_uri_method=").append(cfg.requestUriMethod().value());
        }
        return url.toString();
    }

    // ------------------------------------------------------------------------------------------------ request object

    /**
     * The compact signed request object for {@code tx} (see the class comment).
     *
     * @throws IllegalStateException when the transaction has expired or expires within the current second (its whole
     *                               second {@code exp} would not be after {@code iat}; never rounded up), has no
     *                               usable encryption key (for {@code direct_post.jwt}) or no valid DCQL query, when
     *                               a credential format is unknown or none is configured, when
     *                               {@code requestUriBase} is not a URI or has no host, when the
     *                               {@code x509_san_dns} host is not the {@code response_uri} host (§5.9.3, §8.2), or
     *                               when signing fails
     */
    public String signedRequestObject(final WalletTransaction tx, final WalletProviderConfig cfg,
            final SigningKeyHandle key, final String requestUriBase) {
        return signedRequestObject(tx, cfg, key, requestUriBase, null);
    }

    /**
     * As {@link #signedRequestObject(WalletTransaction, WalletProviderConfig, SigningKeyHandle, String)}, adding the
     * {@code wallet_nonce} a wallet sent with a {@code request_uri_method=post} fetch (OpenID4VP §5.10: "When received,
     * the Verifier MUST use it as the wallet_nonce value in the signed authorization request object"); {@code null}
     * adds nothing.
     */
    public String signedRequestObject(final WalletTransaction tx, final WalletProviderConfig cfg,
            final SigningKeyHandle key, final String requestUriBase, final String walletNonce) {
        final Instant now = clock.instant();
        if (tx.isExpiredAt(now)) {
            throw new IllegalStateException("Wallet transaction has expired");
        }
        final long exp = tx.expiresAt().getEpochSecond();
        if (exp <= now.getEpochSecond()) {
            // exp is whole seconds (rounded down, never up past the transaction): it would not be after iat.
            throw new IllegalStateException("Wallet transaction expires within the current second; "
                    + "the request object's exp would not be after its iat");
        }
        final String clientId = clientId(cfg, key);
        final String responseUri = responseUri(requestUriBase, tx);
        if (cfg.clientIdScheme() == WalletProviderConfig.ClientIdScheme.X509_SAN_DNS
                && !cfg.clientIdHost().trim().equalsIgnoreCase(URI.create(origin(requestUriBase)).getHost())) {
            throw new IllegalStateException("x509_san_dns: the response_uri host must equal clientIdHost");
        }
        final boolean encrypted = cfg.responseMode() == WalletProviderConfig.ResponseMode.DIRECT_POST_JWT;

        final JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .claim("response_type", "vp_token")
                .claim("client_id", clientId)
                .claim("response_mode", cfg.responseMode().value())
                .claim("response_uri", responseUri)
                .claim("nonce", tx.nonce())
                .claim("state", walletState(tx.transactionId()))
                .claim("dcql_query", dcqlQuery(tx))
                .claim("client_metadata", clientMetadata(tx, cfg, encrypted))
                .audience(AUDIENCE)
                .issueTime(Date.from(Instant.ofEpochSecond(tx.createdAt().getEpochSecond())))
                .expirationTime(Date.from(Instant.ofEpochSecond(exp)));
        if (walletNonce != null) {
            builder.claim("wallet_nonce", walletNonce);
        }
        final JWTClaimsSet claims = builder.build();
        final JWSHeader header = new JWSHeader.Builder(key.algorithm())
                .type(new JOSEObjectType(REQUEST_OBJECT_TYP))
                .x509CertChain(x5c(key))
                .build();
        final SignedJWT jwt = new SignedJWT(header, claims);
        try {
            jwt.sign(key.signer());
        } catch (final JOSEException e) {
            throw new IllegalStateException("Could not sign the OpenID4VP request object", e);
        }
        return jwt.serialize();
    }

    private static Map<String, Object> clientMetadata(final WalletTransaction tx, final WalletProviderConfig cfg,
            final boolean encrypted) {
        final Map<String, Object> metadata = new LinkedHashMap<>();
        if (encrypted) {
            metadata.put("jwks", new JWKSet(publicEncryptionKey(tx)).toJSONObject(true));
            metadata.put("encrypted_response_enc_values_supported",
                    RESPONSE_ENC_VALUES.stream().map(EncryptionMethod::getName).toList());
        }
        metadata.put("vp_formats_supported", vpFormats(cfg.credentialFormats()));
        return metadata;
    }

    // ------------------------------------------------------------------------------------------------ DC API

    /** OpenID4VP 1.0 Appendix A.2: the response mode of a DC API request. */
    public static final String DC_API = "dc_api";
    /** OpenID4VP 1.0 Appendix A.2: the encrypted response mode of a DC API request (HAIP §5.2: the Verifier MUST). */
    public static final String DC_API_JWT = "dc_api.jwt";

    /**
     * One {@code DigitalCredentialGetRequest}: what the page passes to
     * {@code navigator.credentials.get({digital: {requests: [{protocol, data}]}})}.
     */
    public record DcApiRequest(String protocol, Map<String, Object> data) {
    }

    /**
     * The request for OpenID4VP over the W3C Digital Credentials API (OpenID4VP 1.0 Appendix A; HAIP 1.0 §5.2).
     *
     * <ul>
     *   <li>{@code response_mode}: {@value #DC_API_JWT} when the provider's response mode is {@code direct_post.jwt}
     *       (the per-transaction encryption key and enc values go into {@code client_metadata} exactly as for the
     *       redirect flow), {@value #DC_API} for the dev-only {@code direct_post}.</li>
     *   <li>Signed ({@code openid4vp-v1-signed}, A.3.2.1): {@code data = {request: <JWS>}}, the same signer, header
     *       ({@code typ}, {@code x5c}) and {@code client_id} as the redirect request object, with
     *       {@code expected_origins} = {@code expectedOrigins} (A.2: REQUIRED), {@code aud}, {@code iat} and
     *       {@code exp} as there. Under {@code x509_san_dns} there is no {@code response_uri} host to match
     *       (§5.9.3: the rule does not apply over the DC API).</li>
     *   <li>Unsigned ({@code openid4vp-v1-unsigned}, A.3.1): the parameters are {@code data} itself, without
     *       {@code client_id} (A.2: MUST be omitted).</li>
     * </ul>
     * Never {@code response_uri}, {@code redirect_uri}, {@code state} (A.2: not defined) or {@code wallet_nonce}.
     *
     * @param expectedOrigins the verifier's own expected origins (configuration; never the caller's request)
     * @throws IllegalStateException when the DC API is off for the provider, no origin is given, the transaction has
     *                               expired (or expires within the current second), or the request cannot be built
     *                               (as {@link #signedRequestObject})
     */
    public DcApiRequest dcApiRequest(final WalletTransaction tx, final WalletProviderConfig cfg,
                                     final SigningKeyHandle key, final List<String> expectedOrigins) {
        if (!cfg.dcApi().enabled()) {
            throw new IllegalStateException("The Digital Credentials API is not enabled for this provider");
        }
        if (expectedOrigins == null || expectedOrigins.isEmpty()) {
            throw new IllegalStateException("A DC API request needs at least one expected origin");
        }
        final Instant now = clock.instant();
        if (tx.isExpiredAt(now)) {
            throw new IllegalStateException("Wallet transaction has expired");
        }
        final long exp = tx.expiresAt().getEpochSecond();
        if (exp <= now.getEpochSecond()) {
            throw new IllegalStateException("Wallet transaction expires within the current second; "
                    + "the request object's exp would not be after its iat");
        }
        final boolean encrypted = cfg.responseMode() == WalletProviderConfig.ResponseMode.DIRECT_POST_JWT;
        final Map<String, Object> params = new LinkedHashMap<>();
        params.put("response_type", "vp_token");
        params.put("response_mode", encrypted ? DC_API_JWT : DC_API);
        params.put("nonce", tx.nonce());
        params.put("dcql_query", dcqlQuery(tx));
        params.put("client_metadata", clientMetadata(tx, cfg, encrypted));
        final WalletProviderConfig.DcApi.RequestType type = cfg.dcApi().request();
        if (type == WalletProviderConfig.DcApi.RequestType.UNSIGNED) {
            return new DcApiRequest(type.protocol(), Collections.unmodifiableMap(params));
        }
        final JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .claim("client_id", clientId(cfg, key))
                .claim("expected_origins", List.copyOf(expectedOrigins));
        params.forEach(builder::claim);
        builder.audience(AUDIENCE)
                .issueTime(Date.from(Instant.ofEpochSecond(tx.createdAt().getEpochSecond())))
                .expirationTime(Date.from(Instant.ofEpochSecond(exp)));
        final JWSHeader header = new JWSHeader.Builder(key.algorithm())
                .type(new JOSEObjectType(REQUEST_OBJECT_TYP))
                .x509CertChain(x5c(key))
                .build();
        final SignedJWT jwt = new SignedJWT(header, builder.build());
        try {
            jwt.sign(key.signer());
        } catch (final JOSEException e) {
            throw new IllegalStateException("Could not sign the OpenID4VP DC API request", e);
        }
        return new DcApiRequest(type.protocol(), Map.of("request", jwt.serialize()));
    }

    /**
     * The public part of the transaction's ephemeral key with {@code use=enc}, {@code alg=ECDH-ES} and its
     * {@code kid}. The stored key must be an EC P-256 key with a {@code kid} and no conflicting {@code use}/{@code alg}.
     */
    private static ECKey publicEncryptionKey(final WalletTransaction tx) {
        if (tx.encryptionJwkJson() == null) {
            throw new IllegalStateException("Wallet transaction has no encryption key");
        }
        final ECKey stored;
        try {
            stored = ECKey.parse(tx.encryptionJwkJson());
        } catch (final ParseException e) {
            throw new IllegalStateException("Wallet transaction encryption key is not an EC JWK");
        }
        if (!Curve.P_256.equals(stored.getCurve())) {
            throw new IllegalStateException("Wallet transaction encryption key is not on P-256");
        }
        if (stored.getKeyID() == null || stored.getKeyID().isBlank()) {
            throw new IllegalStateException("Wallet transaction encryption key has no kid");
        }
        if (stored.getKeyUse() != null && !KeyUse.ENCRYPTION.equals(stored.getKeyUse())
                || stored.getAlgorithm() != null && !JWEAlgorithm.ECDH_ES.equals(stored.getAlgorithm())) {
            throw new IllegalStateException("Wallet transaction encryption key is not an ECDH-ES encryption key");
        }
        return new ECKey.Builder(stored.toPublicJWK()).keyUse(KeyUse.ENCRYPTION).algorithm(JWEAlgorithm.ECDH_ES)
                .keyID(stored.getKeyID()).build();
    }

    /** Never empty ({@code vp_formats_supported} is REQUIRED, §11.1) and never silently drops a format. */
    private static Map<String, Object> vpFormats(final List<String> formats) {
        if (formats == null || formats.isEmpty()) {
            throw new IllegalStateException("No credential formats configured for vp_formats_supported");
        }
        final Map<String, Object> out = new LinkedHashMap<>();
        for (final String format : formats) {
            if (DcqlQueryBuilder.SD_JWT_FORMAT.equals(format)) {
                final Map<String, Object> sdJwt = new LinkedHashMap<>();
                sdJwt.put("sd-jwt_alg_values", JOSE_ALGS);
                sdJwt.put("kb-jwt_alg_values", JOSE_ALGS);
                out.put(format, sdJwt);
            } else if (DcqlQueryBuilder.MDOC_FORMAT.equals(format)) {
                final Map<String, Object> mdoc = new LinkedHashMap<>();
                mdoc.put("issuerauth_alg_values", COSE_ALGS);
                mdoc.put("deviceauth_alg_values", COSE_ALGS);
                out.put(format, mdoc);
            } else {
                throw new IllegalStateException("Unsupported credential format for vp_formats_supported");
            }
        }
        return out;
    }

    private static Map<String, Object> dcqlQuery(final WalletTransaction tx) {
        if (tx.dcqlQueryJson() == null) {
            throw new IllegalStateException("Wallet transaction has no DCQL query");
        }
        try {
            return JSONObjectUtils.parse(tx.dcqlQueryJson());
        } catch (final ParseException e) {
            throw new IllegalStateException("Wallet transaction DCQL query is not a JSON object");
        }
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private static List<Base64> x5c(final SigningKeyHandle key) {
        final List<X509Certificate> chain = key.certificateChain();
        if (chain == null || chain.isEmpty()) {
            throw new IllegalStateException("Signing key has no certificate chain");
        }
        final List<Base64> out = new ArrayList<>(chain.size());
        for (final X509Certificate cert : chain) {
            out.add(Base64.encode(der(cert)));
        }
        return out;
    }

    private static X509Certificate leaf(final SigningKeyHandle key) {
        final List<X509Certificate> chain = key.certificateChain();
        if (chain == null || chain.isEmpty()) {
            throw new IllegalStateException("Signing key has no certificate chain");
        }
        return chain.get(0);
    }

    private static byte[] der(final X509Certificate cert) {
        try {
            return cert.getEncoded();
        } catch (final CertificateEncodingException e) {
            throw new IllegalStateException("Access certificate cannot be encoded", e);
        }
    }

    /**
     * The public origin without trailing slashes. A base that is not a URI ({@code "requestUriBase is not a valid
     * URI"}) or has no host ({@code "requestUriBase has no host"}) is an {@link IllegalStateException}: it is server
     * configuration ({@code idpBaseUrl}), not wallet input.
     */
    private static String origin(final String base) {
        String origin = Objects.requireNonNull(base, "requestUriBase").trim();
        while (origin.endsWith("/")) {
            origin = origin.substring(0, origin.length() - 1);
        }
        final URI uri;
        try {
            uri = new URI(origin);
        } catch (final URISyntaxException e) {
            throw new IllegalStateException("requestUriBase is not a valid URI");
        }
        if (uri.getHost() == null || uri.getHost().isBlank()) {
            throw new IllegalStateException("requestUriBase has no host");
        }
        return origin;
    }

    private static byte[] sha256(final byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String base64Url(final byte[] bytes) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** RFC 3986 percent-encoding (UTF-8): everything except unreserved characters is encoded; never form encoding. */
    private static String pct(final String value) {
        return UriUtils.encode(Objects.requireNonNull(value), StandardCharsets.UTF_8);
    }
}
