/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

import java.net.CookieManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guard: the sign-in rate limit must not be bypassable by spelling the login path differently
 * ({@code /l%6Fgin}, {@code ;} parameters, {@code %2F}, dot segments, double slashes, case, trailing slash). The
 * limiter matches the servlet path {@code RealmRoutingFilter} passes on, which is still percent-encoded, so an
 * encoded spelling would not be counted — but it must then not be served either. Each variant is hammered with
 * wrong passwords past a small login budget; the server must throttle it (429) or refuse the spelling, never keep
 * answering sign-in attempts. Its own boot (small budget, non-Secure cookies over http) and its own PostgreSQL.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "HELIX_SESSION_STORE=queue",
        "database.encryption=0123456789abcdef0123456789abcdef",
        "idp.base.url=http://localhost:8080",
        "sp.base.url=http://localhost:8090",
        "spring.sql.init.mode=always",
        "spring.flyway.enabled=false",
        "helix.ratelimit.login.burst=3",
        "helix.ratelimit.login.refill-per-minute=1",
        "helix.security.cookie-secure=false"})
@DirtiesContext
class LoginRateLimitPathEncodingE2eTest {

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

    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"|value=\"([^\"]+)\"[^>]*name=\"_csrf\"");

    @LocalServerPort
    private int port;

    /**
     * Rate-limit keys are client IP + path, so each spelling has its own budget of 3. Today (rc.8) Spring Security's
     * StrictHttpFirewall refuses any {@code %} or {@code ;} in the URL (400) and Tomcat refuses {@code %2F}, so an
     * encoded spelling never reaches the login processing; a different case or a trailing slash is not the login
     * endpoint (401). This test keeps it that way: no spelling may answer more sign-in attempts than the budget.
     */
    @ParameterizedTest
    @ValueSource(strings = {"/realms/master/l%6Fgin", "/realms/master/%6C%6F%67%69%6E", "/realms/master/login;x=1",
            "/realms/master/login/", "/realms/master/./login", "/realms/master//login", "/realms/master/LOGIN",
            "/realms/m%61ster/login", "/realms/master%2Flogin", "/realms/master/login%3Bx=1", "/realms/master/login"})
    void wrongPasswordsOnAnySpellingOfTheLoginPath_areThrottledOrRefused(final String path) throws Exception {
        final HttpClient http = HttpClient.newBuilder().cookieHandler(new CookieManager())
                .followRedirects(HttpClient.Redirect.NEVER).build();
        final String base = "http://localhost:" + port;
        final HttpResponse<String> page = http.send(HttpRequest.newBuilder(URI.create(base + "/realms/master/login"))
                .GET().build(), HttpResponse.BodyHandlers.ofString());
        final Matcher csrf = CSRF.matcher(page.body());
        assertThat(csrf.find()).as(page.body()).isTrue();
        final String token = csrf.group(1) != null ? csrf.group(1) : csrf.group(2);
        final String form = "username=nobody&password=wrong&_csrf=" + URLEncoder.encode(token, StandardCharsets.UTF_8);

        final List<Integer> statuses = new ArrayList<>();
        final List<String> locations = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            final HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
            statuses.add(r.statusCode());
            locations.add(r.headers().firstValue("Location").orElse(""));
        }

        // Answered sign-in attempts are redirects to the login page with an error; a refused spelling is 4xx.
        final long answeredAttempts = java.util.stream.IntStream.range(0, statuses.size())
                .filter(i -> statuses.get(i) == 302 && locations.get(i).contains("error")).count();
        assertThat(answeredAttempts).as("%s answered %s / %s", path, statuses, locations).isLessThanOrEqualTo(3);
        if (path.equals("/realms/master/login")) {
            // The canonical path really is processed and really is throttled (so the guard above means something).
            assertThat(answeredAttempts).as("%s", statuses).isEqualTo(3);
            assertThat(statuses).as("%s", statuses).contains(429);
        }
    }
}
