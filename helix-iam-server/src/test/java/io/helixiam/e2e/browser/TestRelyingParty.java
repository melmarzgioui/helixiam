/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.helixiam.e2e.OidcFlow;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Predicate;

/**
 * A minimal OIDC relying party on ANOTHER ORIGIN than the IdP: an embedded JDK {@link HttpServer} on
 * {@code http://127.0.0.1:<random port>}, while the IdP is {@code http://localhost:<port>}. Different host and
 * port, so the browser treats them as two origins, like {@code app.monthfold.com} vs {@code auth.monthfold.com}.
 *
 * <h2>Endpoints</h2>
 * <ul>
 *   <li>{@code GET /login?client=<key>[&prompt=…&max_age=…&login_hint=…]}: builds an authorization request
 *       (authorization code, PKCE S256, state, nonce) from the realm's discovery document and 302s the browser
 *       to the IdP. {@code key} is {@link Client#key()}. Any extra query parameter is passed through.</li>
 *   <li>{@code GET /auth/callback}: exchanges the code at the token endpoint with {@code client_secret_basic} +
 *       the PKCE verifier, verifies the ID token against the realm JWKS (signature, {@code iss} = discovery
 *       issuer, {@code aud}, {@code exp}, {@code nonce}) and records a {@link Callback}.</li>
 *   <li>{@code POST /auth/backchannel-logout}: records a {@link BackchannelLogout}, verifying the logout token
 *       against the JWKS of the realm of the client named in its {@code aud}.</li>
 *   <li>{@code GET /logout?client=<key>}: RP-initiated logout (302 to {@code end_session_endpoint} with the last
 *       ID token of that client as {@code id_token_hint}, {@code post_logout_redirect_uri} = {@link #postLogoutUri()}).</li>
 *   <li>{@code GET /}: the post-logout landing page; every hit is recorded ({@link #landings()}).</li>
 * </ul>
 * Everything the RP learns is recorded rather than thrown, so a test can assert on it (and a failure message shows it).
 */
public final class TestRelyingParty implements AutoCloseable {

    public static final String BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String idpBaseUrl;
    private final HttpServer server;
    private final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        final Thread t = new Thread(r, "test-rp");
        t.setDaemon(true);
        return t;
    });
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER).build();
    private final Map<String, Client> clients = new ConcurrentHashMap<>();
    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final Map<String, String> lastIdToken = new ConcurrentHashMap<>();
    private final List<Callback> callbacks = new CopyOnWriteArrayList<>();
    private final List<BackchannelLogout> logouts = new CopyOnWriteArrayList<>();
    private final List<Map<String, String>> landings = new CopyOnWriteArrayList<>();

    private TestRelyingParty(final String idpBaseUrl) throws IOException {
        this.idpBaseUrl = idpBaseUrl;
        server = HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0), 0);
        server.setExecutor(executor);
        server.createContext("/", this::route);
        server.start();
        HarnessEgressGuard.allow(port());
    }

    /** Starts an RP for the IdP at {@code idpBaseUrl} (e.g. {@code http://localhost:8123}, no trailing slash). */
    public static TestRelyingParty start(final String idpBaseUrl) {
        try {
            return new TestRelyingParty(idpBaseUrl);
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // ------------------------------------------------------------------------------------------------
    // Addresses (register these on the client)
    // ------------------------------------------------------------------------------------------------

    public int port() {
        return server.getAddress().getPort();
    }

    /** {@code http://127.0.0.1:<port>}: a different origin from the IdP's {@code http://localhost:<port>}. */
    public String origin() {
        return "http://127.0.0.1:" + port();
    }

    public String callbackUri() {
        return origin() + "/auth/callback";
    }

    /** The post-logout landing page ({@code GET /}). */
    public String postLogoutUri() {
        return origin() + "/";
    }

    public String backchannelLogoutUri() {
        return origin() + "/auth/backchannel-logout";
    }

    // ------------------------------------------------------------------------------------------------
    // Clients
    // ------------------------------------------------------------------------------------------------

    /** Makes the RP act as {@code clientId} of {@code realm} (confidential, {@code client_secret_basic}). */
    public Client register(final String realm, final String clientId, final String clientSecret, final String scope) {
        final Client client = new Client(realm, clientId, clientSecret, scope);
        clients.put(client.key(), client);
        return client;
    }

    /** Where the browser should go to start a sign-in as {@code client}; {@code extra} is passed to the IdP. */
    public String loginUrl(final Client client, final Map<String, String> extra) {
        final StringBuilder url = new StringBuilder(origin()).append("/login?client=").append(enc(client.key()));
        extra.forEach((k, v) -> url.append('&').append(enc(k)).append('=').append(enc(v)));
        return url.toString();
    }

    public String loginUrl(final Client client) {
        return loginUrl(client, Map.of());
    }

    /** RP-initiated logout for {@code client}'s last signed-in session. */
    public String logoutUrl(final Client client) {
        return origin() + "/logout?client=" + enc(client.key());
    }

    // ------------------------------------------------------------------------------------------------
    // What the RP saw
    // ------------------------------------------------------------------------------------------------

    public List<Callback> callbacks() {
        return List.copyOf(callbacks);
    }

    public Optional<Callback> lastCallback() {
        return callbacks.isEmpty() ? Optional.empty() : Optional.of(callbacks.get(callbacks.size() - 1));
    }

    public List<BackchannelLogout> backchannelLogouts() {
        return List.copyOf(logouts);
    }

    /** Query parameters of every hit on the post-logout landing page. */
    public List<Map<String, String>> landings() {
        return List.copyOf(landings);
    }

    /** Waits for a back-channel logout matching {@code filter}. */
    public BackchannelLogout awaitBackchannelLogout(final Predicate<BackchannelLogout> filter, final Duration timeout) {
        final Instant deadline = Instant.now().plus(timeout);
        do {
            for (final BackchannelLogout l : logouts) {
                if (filter.test(l)) {
                    return l;
                }
            }
            sleep(100);
        } while (Instant.now().isBefore(deadline));
        throw new AssertionError("No matching back-channel logout within " + timeout + "; received: " + logouts);
    }

    /** Forgets everything recorded (not the registered clients). */
    public void reset() {
        callbacks.clear();
        logouts.clear();
        landings.clear();
        pending.clear();
        lastIdToken.clear();
    }

    @Override
    public void close() {
        HarnessEgressGuard.revoke(port());
        server.stop(0);
        executor.shutdownNow();
    }

    // ------------------------------------------------------------------------------------------------
    // HTTP
    // ------------------------------------------------------------------------------------------------

    private void route(final HttpExchange ex) throws IOException {
        try (ex) {
            final String path = ex.getRequestURI().getPath();
            final Map<String, String> query = OidcFlow.query(ex.getRequestURI());
            switch (path) {
                case "/login" -> login(ex, query);
                case "/auth/callback" -> callback(ex, query);
                case "/auth/backchannel-logout" -> backchannelLogout(ex);
                case "/logout" -> logout(ex, query);
                case "/" -> {
                    landings.add(query);
                    page(ex, 200, "Signed out", "<main id=\"rp-signed-out\"><h1>Signed out of the test app</h1></main>");
                }
                default -> page(ex, 404, "Not found", "<main><h1>Not found</h1></main>");
            }
        } catch (final RuntimeException e) {
            // A bug in the RP itself: make it visible in the browser and the recorded callbacks.
            callbacks.add(Callback.failed(ex.getRequestURI().getRawQuery(), Map.of(), null, "RP error: " + e));
            page(ex, 500, "RP error", "<main id=\"rp-error\"><pre>" + escape(e.toString()) + "</pre></main>");
        }
    }

    private void login(final HttpExchange ex, final Map<String, String> query) throws IOException {
        final Client client = clients.get(query.getOrDefault("client", ""));
        if (client == null) {
            page(ex, 400, "Unknown client", "<main><h1>Unknown client " + escape(query.get("client")) + "</h1></main>");
            return;
        }
        final JsonNode discovery = discovery(client);
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final String state = randomToken();
        final String nonce = randomToken();
        pending.put(state, new Pending(client, pkce.verifier(), nonce));
        final Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", client.clientId());
        params.put("redirect_uri", callbackUri());
        params.put("scope", client.scope());
        params.put("state", state);
        params.put("nonce", nonce);
        params.put("code_challenge", pkce.challenge());
        params.put("code_challenge_method", "S256");
        query.forEach((k, v) -> {
            if (!"client".equals(k)) {
                params.put(k, v);
            }
        });
        redirect(ex, discovery.path("authorization_endpoint").asText() + "?" + form(params));
    }

    private void callback(final HttpExchange ex, final Map<String, String> query) throws IOException {
        final Callback result = handleCallback(ex.getRequestURI().getRawQuery(), query);
        callbacks.add(result);
        final String status = result.ok() ? "ok" : "error";
        page(ex, result.ok() ? 200 : 400, "Test app",
                "<main id=\"rp-callback\" data-status=\"" + status + "\"><h1>"
                        + (result.ok() ? "Signed in to the test app" : "Sign-in failed") + "</h1>"
                        + "<p id=\"rp-sub\">" + escape(result.subject()) + "</p>"
                        + "<pre id=\"rp-detail\">" + escape(result.ok() ? "" : result.failure()) + "</pre></main>");
    }

    private Callback handleCallback(final String rawQuery, final Map<String, String> query) {
        final Pending p = query.get("state") == null ? null : pending.remove(query.get("state"));
        if (query.containsKey("error")) {
            return Callback.failed(rawQuery, query, p, "authorization error: " + query.get("error")
                    + " " + query.getOrDefault("error_description", ""));
        }
        if (p == null) {
            return Callback.failed(rawQuery, query, null, "unknown or reused state " + query.get("state"));
        }
        final String code = query.get("code");
        if (code == null || code.isBlank()) {
            return Callback.failed(rawQuery, query, p, "no code in the callback");
        }
        final Client client = p.client();
        final JsonNode discovery = discovery(client);
        final HttpResponse<String> token = postForm(discovery.path("token_endpoint").asText(), Map.of(
                "grant_type", "authorization_code",
                "code", code,
                "redirect_uri", callbackUri(),
                "code_verifier", p.verifier()), OidcFlow.basic(client.clientId(), client.clientSecret()));
        if (token.statusCode() != 200) {
            return Callback.failed(rawQuery, query, p, "token endpoint HTTP " + token.statusCode() + ": " + token.body());
        }
        final JsonNode tokens = readJson(token.body());
        final String idToken = tokens.path("id_token").asText(null);
        if (idToken == null) {
            return Callback.failed(rawQuery, query, p, "no id_token in " + token.body());
        }
        final String issuer = discovery.path("issuer").asText();
        final JWTClaimsSet claims;
        try {
            claims = processor(discovery, new DefaultJWTClaimsVerifier<>(client.clientId(),
                    new JWTClaimsSet.Builder().issuer(issuer).build(), Set.of("sub", "iat", "exp"))).process(idToken, null);
        } catch (final Exception e) {
            return Callback.failed(rawQuery, query, p, "ID token rejected (issuer " + issuer + "): " + e.getMessage());
        }
        if (!p.nonce().equals(claims.getClaim("nonce"))) {
            return Callback.failed(rawQuery, query, p, "nonce mismatch: " + claims.getClaim("nonce"));
        }
        lastIdToken.put(client.key(), idToken);
        return new Callback(Instant.now(), rawQuery, query, client, code, tokens, idToken, claims, null);
    }

    private void backchannelLogout(final HttpExchange ex) throws IOException {
        if (!"POST".equals(ex.getRequestMethod())) {
            ex.sendResponseHeaders(405, -1);
            return;
        }
        final String body;
        try (InputStream in = ex.getRequestBody()) {
            body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        final String token = OidcFlow.query(URI.create("x:/?" + body)).get("logout_token");
        final BackchannelLogout record = verifyLogoutToken(token, ex.getRequestHeaders().getFirst("Content-Type"));
        logouts.add(record);
        final int status = record.verified() ? 200 : 400;
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(status, -1);
    }

    private BackchannelLogout verifyLogoutToken(final String token, final String contentType) {
        if (token == null || token.isBlank()) {
            return new BackchannelLogout(Instant.now(), token, contentType, Map.of(), null, null, "no logout_token");
        }
        final Map<String, Object> unverified;
        try {
            unverified = SignedJWT.parse(token).getJWTClaimsSet().getClaims();
        } catch (final java.text.ParseException e) {
            return new BackchannelLogout(Instant.now(), token, contentType, Map.of(), null, null, "not a JWT: " + e.getMessage());
        }
        final Object aud = unverified.get("aud");
        final List<String> audiences = aud instanceof List<?> l ? l.stream().map(String::valueOf).toList()
                : aud == null ? List.of() : List.of(String.valueOf(aud));
        // aud is the client_id; with the same client_id in several realms, try each (each has its own JWKS).
        String failure = "no registered client matches aud " + audiences;
        for (final Client client : clients.values()) {
            if (!audiences.contains(client.clientId())) {
                continue;
            }
            try {
                final JsonNode discovery = discovery(client);
                final JWTClaimsSet claims = processor(discovery, new DefaultJWTClaimsVerifier<>(new java.util.HashSet<>(List.of(client.clientId())), // Set.of(...).contains(null) throws
                        new JWTClaimsSet.Builder().issuer(discovery.path("issuer").asText()).build(),
                        Set.of("iat", "jti", "events"), Set.of("nonce"))).process(token, null);
                final Object events = claims.getClaim("events");
                if (!(events instanceof Map<?, ?> m) || !m.containsKey(BACKCHANNEL_LOGOUT_EVENT)) {
                    failure = "events claim lacks " + BACKCHANNEL_LOGOUT_EVENT + ": " + events;
                    continue;
                }
                if (claims.getSubject() == null && claims.getClaim("sid") == null) {
                    failure = "neither sub nor sid present";
                    continue;
                }
                return new BackchannelLogout(Instant.now(), token, contentType, unverified, client, claims, null);
            } catch (final Exception e) {
                failure = "rejected for " + client.key() + ": " + e.getMessage();
            }
        }
        return new BackchannelLogout(Instant.now(), token, contentType, unverified, null, null, failure);
    }

    private void logout(final HttpExchange ex, final Map<String, String> query) throws IOException {
        final Client client = clients.get(query.getOrDefault("client", ""));
        if (client == null) {
            page(ex, 400, "Unknown client", "<main><h1>Unknown client</h1></main>");
            return;
        }
        final Map<String, String> params = new LinkedHashMap<>();
        final String idToken = lastIdToken.get(client.key());
        if (idToken != null) {
            params.put("id_token_hint", idToken);
        }
        params.put("client_id", client.clientId());
        params.put("post_logout_redirect_uri", postLogoutUri());
        params.put("state", randomToken());
        redirect(ex, discovery(client).path("end_session_endpoint").asText() + "?" + form(params));
    }

    // ------------------------------------------------------------------------------------------------

    private DefaultJWTProcessor<SecurityContext> processor(final JsonNode discovery,
                                                          final DefaultJWTClaimsVerifier<SecurityContext> claims) {
        final JWKSet jwks;
        try {
            jwks = JWKSet.parse(get(discovery.path("jwks_uri").asText()));
        } catch (final java.text.ParseException e) {
            throw new IllegalStateException("JWKS is not a JWK set", e);
        }
        final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSTypeVerifier((type, context) -> { }); // logout tokens are "logout+jwt", ID tokens "JWT"
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(
                Set.of(JWSAlgorithm.RS256, JWSAlgorithm.PS256, JWSAlgorithm.ES256), new ImmutableJWKSet<>(jwks)));
        processor.setJWTClaimsSetVerifier(claims);
        return processor;
    }

    /** The realm's discovery document, fetched on the RP's back channel from the same base URL the browser uses. */
    private JsonNode discovery(final Client client) {
        return readJson(get(idpBaseUrl + "/realms/" + client.realm() + "/.well-known/openid-configuration"));
    }

    private String get(final String url) {
        try {
            final HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10))
                    .GET().build(), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) {
                throw new IllegalStateException("GET " + url + " -> HTTP " + r.statusCode());
            }
            return r.body();
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private HttpResponse<String> postForm(final String url, final Map<String, String> fields, final String authorization) {
        try {
            return http.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .header("Authorization", authorization)
                    .POST(HttpRequest.BodyPublishers.ofString(form(fields))).build(), HttpResponse.BodyHandlers.ofString());
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static JsonNode readJson(final String body) {
        try {
            return JSON.readTree(body);
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void redirect(final HttpExchange ex, final String location) throws IOException {
        ex.getResponseHeaders().set("Location", location);
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(302, -1);
    }

    private static void page(final HttpExchange ex, final int status, final String title, final String main)
            throws IOException {
        final byte[] html = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>" + escape(title)
                + "</title></head><body>" + main + "</body></html>").getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(status, html.length);
        ex.getResponseBody().write(html);
    }

    private static String form(final Map<String, String> fields) {
        final StringBuilder out = new StringBuilder();
        fields.forEach((k, v) -> {
            if (out.length() > 0) {
                out.append('&');
            }
            out.append(enc(k)).append('=').append(enc(v));
        });
        return out.toString();
    }

    private static String enc(final String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
    }

    private static String escape(final String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String randomToken() {
        final byte[] b = new byte[16];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static void sleep(final long millis) {
        try {
            Thread.sleep(millis);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------------------------------------

    /** A client the RP signs in as. {@link #key()} identifies it in {@code /login?client=}. */
    public record Client(String realm, String clientId, String clientSecret, String scope) {

        public String key() {
            return realm + "/" + clientId;
        }
    }

    private record Pending(Client client, String verifier, String nonce) {
    }

    /**
     * One hit on {@code /auth/callback}. {@code failure} is null when the code was exchanged and the ID token
     * verified; otherwise it says why not (authorization error, token endpoint error, invalid ID token, …).
     */
    public record Callback(Instant at, String rawQuery, Map<String, String> params, Client client, String code,
                           JsonNode tokenResponse, String idToken, JWTClaimsSet idTokenClaims, String failure) {

        static Callback failed(final String rawQuery, final Map<String, String> params, final Pending pending,
                               final String failure) {
            return new Callback(Instant.now(), rawQuery, params, pending == null ? null : pending.client(),
                    params.get("code"), null, null, null, failure);
        }

        public boolean ok() {
            return failure == null;
        }

        public String subject() {
            return idTokenClaims == null ? null : idTokenClaims.getSubject();
        }

        public String accessToken() {
            return tokenResponse == null ? null : tokenResponse.path("access_token").asText(null);
        }

        public String refreshToken() {
            return tokenResponse == null ? null : tokenResponse.path("refresh_token").asText(null);
        }

        @Override
        public String toString() {
            return "Callback[" + (ok() ? "ok sub=" + subject() : "FAILED " + failure) + ", client="
                    + (client == null ? null : client.key()) + ", params=" + params.keySet() + "]";
        }
    }

    /**
     * One back-channel logout POST. {@code claims} is the unverified payload (always set when the token parsed);
     * {@code verifiedClaims} is set only when the token verified against the realm JWKS of the client in its
     * {@code aud} (with {@code iss}, {@code aud}, {@code iat}, {@code jti}, {@code events}, and no {@code nonce});
     * {@code failure} says why it did not.
     */
    public record BackchannelLogout(Instant at, String logoutToken, String contentType, Map<String, Object> claims,
                                    Client client, JWTClaimsSet verifiedClaims, String failure) {

        public boolean verified() {
            return verifiedClaims != null;
        }

        @Override
        public String toString() {
            return "BackchannelLogout[" + (verified() ? "verified" : "UNVERIFIED " + failure) + ", claims=" + claims + "]";
        }
    }
}
