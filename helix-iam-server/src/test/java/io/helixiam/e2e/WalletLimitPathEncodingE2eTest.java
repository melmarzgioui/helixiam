/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ApplicationContext;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Final review F3, regression guard: the EUDI wallet's limits must not be bypassable by spelling a path differently.
 * {@code RateLimitFilter} matches the servlet path {@code RealmRoutingFilter} passes on, and
 * {@code WalletRequestBodyLimitFilter} the raw request URI, both still percent-encoded, so an encoded spelling
 * ({@code /br%6Fker/<alias>}, {@code /%6Fid4vp/...}) is not counted — it must then not be served either. Today Spring
 * Security's StrictHttpFirewall refuses any {@code %} or {@code ;} in the URL (400) and Tomcat refuses {@code %2F}; a
 * different case or a trailing slash is not the endpoint. This test keeps it that way: no spelling may start more
 * wallet logins than the {@code wallet-start} budget, answer more OpenID4VP requests than the {@code /oid4vp} budget,
 * or have an over-limit body processed. Mirrors {@code LoginRateLimitPathEncodingE2eTest}. Its own boot (small
 * budgets) and its own PostgreSQL.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "HELIX_SESSION_STORE=queue",
        "database.encryption=0123456789abcdef0123456789abcdef",
        "idp.base.url=http://localhost:8080",
        "sp.base.url=http://localhost:8090",
        "spring.sql.init.mode=always",
        "spring.flyway.enabled=false",
        "helix.ratelimit.wallet-start.burst=3",
        "helix.ratelimit.wallet-start.refill-per-minute=1",
        "helix.ratelimit.wallet.burst=3",
        "helix.ratelimit.wallet.refill-per-minute=1",
        "helix.security.cookie-secure=false"})
@DirtiesContext
class WalletLimitPathEncodingE2eTest {

    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("helixiam").withUsername("helixiam").withPassword("helixiam");

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void properties(final DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.readonly.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.data.redis.host", () -> "127.0.0.1");
        registry.add("spring.data.redis.port", () -> "1");
        registry.add("spring.data.redis.timeout", () -> "500ms");
    }

    /** The wallet provider every spelling below names (one per test: each test gets its own budget key). */
    private static final String ALIAS = "eudi-wallet";
    /** Over {@code helix.wallet.max-request-bytes} (256 KB). */
    private static final int OVER_LIMIT = 300 * 1024;

    @LocalServerPort
    private int port;

    @Autowired
    private ApplicationContext context;

    @BeforeEach
    void installWallet() {
        final WalletE2eFixture wallet = new WalletE2eFixture(context);
        wallet.install("master", wallet.yamlProvider(ALIAS));
    }

    /**
     * Rate-limit keys are client IP + group, so each spelling would have its own budget only if it were served. No
     * spelling may start more wallet logins (a 302 to the wallet page) than the budget of 3.
     */
    @ParameterizedTest
    @ValueSource(strings = {"/realms/master/br%6Fker/" + ALIAS, "/realms/master/%62%72%6F%6B%65%72/" + ALIAS,
            "/realms/master/broker/eudi-w%61llet", "/realms/master/broker/" + ALIAS + ";x=1",
            "/realms/master/broker/" + ALIAS + "/", "/realms/master/./broker/" + ALIAS,
            "/realms/master//broker/" + ALIAS, "/realms/master/BROKER/" + ALIAS, "/realms/m%61ster/broker/" + ALIAS,
            "/realms/master/broker%2F" + ALIAS, "/realms/master/broker/" + ALIAS})
    void walletStarts_onAnySpellingOfTheBrokerPath_areThrottledOrRefused(final String path) throws Exception {
        final List<Reply> replies = send(path, 8);
        final List<Integer> statuses = replies.stream().map(Reply::status).toList();
        final List<String> locations = replies.stream().map(Reply::location).toList();

        if (path.contains("%") || path.contains(";") || path.contains("//") || path.contains("/./")) {
            assertThat(replies).as("%s is refused outright: %s", path, statuses).allMatch(Reply::refused);
        }
        // A started wallet login is a redirect to the wallet page; a refused spelling is 4xx.
        final long started = java.util.stream.IntStream.range(0, statuses.size())
                .filter(i -> statuses.get(i) == 302 && locations.get(i).contains("/wallet?tx=")).count();
        assertThat(started).as("%s answered %s / %s", path, statuses, locations).isLessThanOrEqualTo(3);
        if (path.equals("/realms/master/broker/" + ALIAS)) {
            // The canonical path really starts wallet logins and really is throttled (so the guard means something).
            assertThat(started).as("%s / %s", statuses, locations).isEqualTo(3);
            assertThat(statuses).as("%s", statuses).contains(429);
        }
    }

    /**
     * Every re-spelled OpenID4VP path (percent-encoded, {@code ;} parameter, encoded slash, dot segment, double slash)
     * is refused (the firewall's 400, an encoded realm's "does not exist" 404) or throttled (429: the {@code /oid4vp}
     * budget is per client IP, and a {@code ;} spelling still counts against it) — never answered by the endpoints.
     */
    @ParameterizedTest
    @ValueSource(strings = {"/realms/master/%6Fid4vp/" + ALIAS + "/request/abc",
            "/realms/master/%6F%69%64%34%76%70/" + ALIAS + "/request/abc",
            "/realms/master/oid4vp/" + ALIAS + "/request/abc;x=1", "/realms/master/oid4vp%2F" + ALIAS + "/request/abc",
            "/realms/master/./oid4vp/" + ALIAS + "/request/abc", "/realms/master//oid4vp/" + ALIAS + "/request/abc",
            "/realms/m%61ster/oid4vp/" + ALIAS + "/request/abc"})
    void openId4VpRequests_onAReSpelledPath_areRefused(final String path) throws Exception {
        final List<Reply> replies = send(path, 8);
        assertThat(replies).as("%s: %s", path, replies).allMatch(Reply::refused);
    }

    /**
     * The canonical OpenID4VP path is answered (an unknown request id: 404) and really is throttled: at most the budget
     * of 3 (less when a re-spelled path above already spent some of this IP's budget), then 429.
     */
    @Test
    void openId4VpRequests_onTheCanonicalPath_areThrottled() throws Exception {
        final List<Reply> replies = send("/realms/master/oid4vp/" + ALIAS + "/request/abc", 8);

        assertThat(replies.stream().filter(r -> r.status() == 404).count()).as("%s", replies).isLessThanOrEqualTo(3);
        assertThat(replies.get(replies.size() - 1).status()).as("%s", replies).isEqualTo(429);
    }

    /** An over-limit body is refused on every spelling of the response endpoint, never parsed and processed. */
    @ParameterizedTest
    @ValueSource(strings = {"/realms/master/%6Fid4vp/" + ALIAS + "/response/abc",
            "/realms/master/oid4vp/" + ALIAS + "/resp%6Fnse/abc", "/realms/master/oid4vp/" + ALIAS + "/response/abc;x=1",
            "/realms/m%61ster/oid4vp/" + ALIAS + "/response/abc", "/realms/master/oid4vp/" + ALIAS + "/response/abc"})
    void anOverLimitResponseBody_isRefusedOnEverySpelling(final String path) throws Exception {
        final String body = "response=" + "A".repeat(OVER_LIMIT);

        final HttpResponse<String> r = client().send(HttpRequest.newBuilder(uri(path))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());

        final Reply reply = new Reply(r.statusCode(), r.body() == null ? "" : r.body(), "");
        assertThat(reply.refused() || reply.status() == 413).as("%s -> %s", path, reply).isTrue();
        if (path.equals("/realms/master/oid4vp/" + ALIAS + "/response/abc")) {
            assertThat(r.statusCode()).isEqualTo(413); // the body limit itself
        }
    }

    @Test
    void theWalletIsInstalled() throws Exception {
        // sanity for the guards above: the canonical start reaches the wallet page
        final HttpResponse<String> r = client().send(HttpRequest.newBuilder(uri("/realms/master/login")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(r.body()).contains("/broker/" + ALIAS);
    }

    /** One answer: its status, body and {@code Location}. */
    private record Reply(int status, String body, String location) {

        /** Refused before any wallet code ran: the firewall (400), the throttle (429) or an unknown realm (404). */
        boolean refused() {
            return status == 400 || status == 429 || status == 404 && body.contains("does not exist");
        }
    }

    /** {@code times} GETs of {@code path} in one browser session. */
    private List<Reply> send(final String path, final int times) throws Exception {
        final HttpClient http = client();
        final List<Reply> replies = new ArrayList<>();
        for (int i = 0; i < times; i++) {
            final HttpResponse<String> r = http.send(HttpRequest.newBuilder(uri(path))
                    .header("Accept", "application/oauth-authz-req+jwt").GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            replies.add(new Reply(r.statusCode(), r.body() == null ? "" : r.body(),
                    r.headers().firstValue("Location").orElse("")));
        }
        return replies;
    }

    private static HttpClient client() {
        return HttpClient.newBuilder().cookieHandler(new CookieManager()).followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    private URI uri(final String path) {
        return URI.create("http://localhost:" + port + path);
    }
}
