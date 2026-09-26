/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Drives the OAuth2/OIDC protocol endpoints of one realm over real HTTP, as a relying party + browser would.
 *
 * <p>All endpoints are realm-prefixed ({@code /realms/{realm}/…}) — flat protocol paths are 404'd by
 * {@code RealmRoutingFilter}. The issuer SAS reports is derived from the request, i.e.
 * {@code http://localhost:{port}/realms/{realm}}.
 *
 * <h2>Authorization-code + PKCE login, as the server performs it</h2>
 * <ol>
 *   <li>{@code GET /realms/{r}/oauth2/authorize?…} (anonymous) → 302 to {@code /realms/{r}/login}; the
 *       authorize request is saved in the HTTP session.</li>
 *   <li>{@code GET /realms/{r}/login} → 200 login page with {@code <form action="/realms/{r}/login">}
 *       carrying a hidden {@code _csrf} input (+ an {@code XSRF-TOKEN} cookie).</li>
 *   <li>{@code POST /realms/{r}/login} {@code username,password,_csrf} → 302 back to the saved
 *       {@code /realms/{r}/oauth2/authorize?…&continue} (only when {@code mfa.enabled=false} and the flow
 *       engine is off — otherwise the success handler routes to {@code /mfa/…} or {@code /flow}).</li>
 *   <li>{@code GET …/oauth2/authorize?…} (now authenticated) → either 302 to {@code redirect_uri?code=…&state=…},
 *       or — for a client with {@code consentRequired} and non-openid scopes — 302 to
 *       {@code /realms/{r}/oauth2/consent}, whose form POSTs back to {@code /realms/{r}/oauth2/authorize}.</li>
 *   <li>{@code POST /realms/{r}/oauth2/token} ({@code client_secret_basic}) with {@code code_verifier}.</li>
 * </ol>
 */
public final class OidcFlow {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final E2eHttp http;
    private final String realm;

    /** {@code http} is the user agent (its cookie jar carries the login session). */
    public OidcFlow(final E2eHttp http, final String realm) {
        this.http = http;
        this.realm = realm;
    }

    public String realm() {
        return realm;
    }

    /** Server-relative realm path, e.g. {@code /realms/master}. */
    public String realmPath() {
        return "/realms/" + realm;
    }

    // ------------------------------------------------------------------------------------------------
    // Discovery / JWKS
    // ------------------------------------------------------------------------------------------------

    /** The realm's OIDC discovery document ({@code /.well-known/openid-configuration}). */
    public JsonNode discovery() {
        final E2eHttp.Response r = http.get(realmPath() + "/.well-known/openid-configuration");
        expectStatus(r, 200);
        return r.json();
    }

    /** The discovery {@code issuer}. */
    public String issuer() {
        return discovery().path("issuer").asText();
    }

    /** The realm's public JWKS ({@code /oauth2/jwks}). */
    public JWKSet jwks() {
        final E2eHttp.Response r = http.get(realmPath() + "/oauth2/jwks");
        expectStatus(r, 200);
        try {
            return JWKSet.parse(r.body());
        } catch (final java.text.ParseException e) {
            throw new AssertionError("JWKS is not a JWK set: " + r, e);
        }
    }

    // ------------------------------------------------------------------------------------------------
    // Grants
    // ------------------------------------------------------------------------------------------------

    /**
     * Full browser authorization-code + PKCE (S256) flow for {@code username}/{@code password}, then the
     * code→token exchange authenticated with {@code client_secret_basic}.
     *
     * @param scope space-separated scopes, e.g. {@code "openid profile"}
     */
    public Tokens authorizationCode(final String clientId, final String clientSecret, final String redirectUri,
                                    final String username, final String password, final String scope) {
        final AuthorizationResult auth = authorize(clientId, redirectUri, username, password, scope);
        return exchangeCode(clientId, clientSecret, redirectUri, auth.code(), auth.pkce().verifier());
    }

    /**
     * Steps 1–4 of the flow (see class javadoc): logs the user in through the real login form and returns the
     * authorization {@code code} read off the redirect to {@code redirectUri} (which is never requested).
     */
    public AuthorizationResult authorize(final String clientId, final String redirectUri, final String username,
                                         final String password, final String scope) {
        return authorize(clientId, redirectUri, username, password, scope, null);
    }

    /**
     * A second-factor step: given the page the login landed on (an MFA page, 200), submit it and return the
     * response. Invoked until the flow reaches {@code redirect_uri}; {@code null} = password-only login.
     */
    @FunctionalInterface
    public interface SecondFactor {
        E2eHttp.Response submit(E2eHttp.Response page);
    }

    /** As {@link #authorize(String, String, String, String, String)}, answering MFA pages with {@code secondFactor}. */
    public AuthorizationResult authorize(final String clientId, final String redirectUri, final String username,
                                         final String password, final String scope, final SecondFactor secondFactor) {
        final Pkce pkce = Pkce.create();
        final String state = randomToken();
        final String nonce = randomToken();
        final String authorizeUrl = realmPath() + "/oauth2/authorize"
                + "?response_type=code"
                + "&client_id=" + enc(clientId)
                + "&redirect_uri=" + enc(redirectUri)
                + "&scope=" + enc(scope)
                + "&state=" + enc(state)
                + "&nonce=" + enc(nonce)
                + "&code_challenge=" + enc(pkce.challenge())
                + "&code_challenge_method=S256";

        // 1-2: anonymous authorize → login page.
        E2eHttp.Response r = http.followRedirectsUntil(http.get(authorizeUrl), hit -> hit.locationStartsWith(redirectUri));
        if (r.locationStartsWith(redirectUri)) {
            // Already signed in in this browser (SSO): the code comes straight back.
            return toResult(r, state, nonce, pkce);
        }
        if (r.status() != 200) {
            throw new AssertionError("Expected the login page (200), got: " + r + "\n" + http.trail(10));
        }
        final String loginAction = E2eHttp.formAction(r.body(), "name=\"password\"")
                .orElseThrow(() -> new AssertionError("Expected the login form, got: " + r + "\n" + http.trail(10)));

        // 3: submit credentials (+ the form's hidden fields, incl. _csrf).
        final Map<String, String> form = new LinkedHashMap<>(E2eHttp.hiddenInputs(
                E2eHttp.form(r.body(), "name=\"password\"").orElseThrow()));
        form.put("username", username);
        form.put("password", password);
        E2eHttp.Response after = http.postForm(loginAction, form);
        if (after.isRedirect() && after.location().getQuery() != null
                && after.location().getPath().endsWith("/login") && after.location().getQuery().contains("error")) {
            throw new AssertionError("Login rejected for '" + username + "': " + after + "\n" + http.trail(10));
        }

        // 4: back to authorize → (second factor?) → (consent?) → redirect_uri?code=…
        after = http.followRedirectsUntil(after, hit -> hit.locationStartsWith(redirectUri));
        for (int i = 0; secondFactor != null && i < 5 && after.status() == 200 && after.uri().getPath().contains("/mfa/"); i++) {
            after = http.followRedirectsUntil(secondFactor.submit(after), hit -> hit.locationStartsWith(redirectUri));
        }
        if (!after.locationStartsWith(redirectUri) && after.status() == 200
                && after.body() != null && after.body().contains("name=\"state\"")) {
            after = http.followRedirectsUntil(approveConsent(after), hit -> hit.locationStartsWith(redirectUri));
        }
        if (!after.locationStartsWith(redirectUri)) {
            throw new AssertionError("Expected a redirect to " + redirectUri + " with a code, got: " + after
                    + "\n" + http.trail(15));
        }
        return toResult(after, state, nonce, pkce);
    }

    /** Submits the consent page's form, approving every pre-checked scope. */
    private E2eHttp.Response approveConsent(final E2eHttp.Response consentPage) {
        final String formHtml = E2eHttp.form(consentPage.body(), "name=\"state\"")
                .orElseThrow(() -> new AssertionError("No consent form: " + consentPage));
        final String action = E2eHttp.formAction(consentPage.body(), "name=\"state\"").orElseThrow();
        final List<Map.Entry<String, String>> fields = new ArrayList<>();
        E2eHttp.hiddenInputs(formHtml).forEach((k, v) -> fields.add(new AbstractMap.SimpleEntry<>(k, v)));
        E2eHttp.checkedValues(formHtml, "scope").forEach(s -> fields.add(new AbstractMap.SimpleEntry<>("scope", s)));
        return http.postForm(action, fields);
    }

    /** Code → tokens at {@code /oauth2/token} with {@code client_secret_basic} + the PKCE verifier. */
    public Tokens exchangeCode(final String clientId, final String clientSecret, final String redirectUri,
                               final String code, final String codeVerifier) {
        final Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("redirect_uri", redirectUri);
        form.put("code_verifier", codeVerifier);
        return tokenRequest(clientId, clientSecret, form);
    }

    /** {@code client_credentials} grant ({@code scope} may be null for the client's defaults). */
    public Tokens clientCredentials(final String clientId, final String clientSecret, final String scope) {
        final Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "client_credentials");
        if (scope != null) {
            form.put("scope", scope);
        }
        return tokenRequest(clientId, clientSecret, form);
    }

    /** {@code refresh_token} grant. */
    public Tokens refresh(final String clientId, final String clientSecret, final String refreshToken) {
        final Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", refreshToken);
        return tokenRequest(clientId, clientSecret, form);
    }

    /** Raw {@code POST /oauth2/token} with {@code client_secret_basic}; returns the response unasserted. */
    public E2eHttp.Response tokenEndpoint(final String clientId, final String clientSecret, final Map<String, String> form) {
        return http.postForm(realmPath() + "/oauth2/token", form, "Authorization", basic(clientId, clientSecret));
    }

    private Tokens tokenRequest(final String clientId, final String clientSecret, final Map<String, String> form) {
        final E2eHttp.Response r = tokenEndpoint(clientId, clientSecret, form);
        expectStatus(r, 200);
        final JsonNode json = r.json();
        return new Tokens(text(json, "access_token"), text(json, "id_token"), text(json, "refresh_token"), json);
    }

    // ------------------------------------------------------------------------------------------------
    // Resource-side endpoints
    // ------------------------------------------------------------------------------------------------

    /** {@code GET /userinfo} with the bearer access token (response unasserted). */
    public E2eHttp.Response userinfo(final String accessToken) {
        return http.get(realmPath() + "/userinfo", "Authorization", "Bearer " + accessToken);
    }

    /** RFC 7662 introspection, authenticated as {@code clientId} ({@code client_secret_basic}). */
    public JsonNode introspect(final String clientId, final String clientSecret, final String token) {
        final E2eHttp.Response r = http.postForm(realmPath() + "/oauth2/introspect", Map.of("token", token),
                "Authorization", basic(clientId, clientSecret));
        expectStatus(r, 200);
        return r.json();
    }

    // ------------------------------------------------------------------------------------------------
    // JWT helpers
    // ------------------------------------------------------------------------------------------------

    /** Decodes a JWT's payload WITHOUT verifying it (for assertions on claim shape). */
    public static Map<String, Object> claims(final String jwt) {
        final String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            throw new AssertionError("Not a JWT: " + jwt);
        }
        try {
            return JSON.readValue(Base64.getUrlDecoder().decode(parts[1]), new TypeReference<Map<String, Object>>() { });
        } catch (final java.io.IOException e) {
            throw new AssertionError("JWT payload is not JSON", e);
        }
    }

    /**
     * Verifies {@code jwt}'s signature against this realm's JWKS (RS256/PS256/ES256) and returns its claims.
     * Throws if the signature does not verify or the token is expired.
     */
    public JWTClaimsSet verify(final String jwt) {
        final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        // Accept any JOSE "typ" (access tokens may be "at+jwt"); we only care about the signature here.
        processor.setJWSTypeVerifier((type, context) -> { });
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(
                Set.of(JWSAlgorithm.RS256, JWSAlgorithm.PS256, JWSAlgorithm.ES256),
                new ImmutableJWKSet<>(jwks())));
        try {
            return processor.process(jwt, null);
        } catch (final Exception e) {
            throw new AssertionError("JWT did not verify against " + realmPath() + "/oauth2/jwks: " + e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------------------------------------------

    private AuthorizationResult toResult(final E2eHttp.Response redirect, final String expectedState,
                                         final String nonce, final Pkce pkce) {
        final Map<String, String> query = query(redirect.location());
        if (query.containsKey("error")) {
            throw new AssertionError("Authorization error: " + query);
        }
        if (!expectedState.equals(query.get("state"))) {
            throw new AssertionError("state mismatch: expected " + expectedState + " in " + redirect.location());
        }
        final String code = query.get("code");
        if (code == null) {
            throw new AssertionError("No code in " + redirect.location());
        }
        return new AuthorizationResult(code, expectedState, nonce, pkce);
    }

    /** Decoded query parameters of a URI (first value wins). */
    public static Map<String, String> query(final URI uri) {
        final Map<String, String> out = new LinkedHashMap<>();
        final String raw = uri.getRawQuery();
        if (raw == null) {
            return out;
        }
        for (final String pair : raw.split("&")) {
            final int eq = pair.indexOf('=');
            final String k = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
            final String v = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            out.putIfAbsent(k, v);
        }
        return out;
    }

    static void expectStatus(final E2eHttp.Response r, final int status) {
        if (r.status() != status) {
            throw new AssertionError("Expected HTTP " + status + " but got: " + r);
        }
    }

    public static String basic(final String clientId, final String clientSecret) {
        // RFC 6749 §2.3.1: form-urlencode id + secret before base64.
        final String pair = enc(clientId) + ":" + enc(clientSecret == null ? "" : clientSecret);
        return "Basic " + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8));
    }

    private static String text(final JsonNode json, final String field) {
        final JsonNode n = json.get(field);
        return n == null || n.isNull() ? null : n.asText();
    }

    private static String enc(final String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String randomToken() {
        final byte[] b = new byte[16];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** Token-endpoint result; {@code raw} is the full JSON response. */
    public record Tokens(String accessToken, String idToken, String refreshToken, JsonNode raw) {
    }

    /** The authorization response (code + the request's state/nonce/PKCE pair). */
    public record AuthorizationResult(String code, String state, String nonce, Pkce pkce) {
    }

    /** An RFC 7636 PKCE pair (S256). */
    public record Pkce(String verifier, String challenge) {

        public static Pkce create() {
            final String verifier = randomToken() + randomToken();
            try {
                final byte[] digest = MessageDigest.getInstance("SHA-256")
                        .digest(verifier.getBytes(StandardCharsets.US_ASCII));
                return new Pkce(verifier, Base64.getUrlEncoder().withoutPadding().encodeToString(digest));
            } catch (final java.security.NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
