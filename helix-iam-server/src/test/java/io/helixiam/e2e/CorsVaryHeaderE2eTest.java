/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every response that passes HelixIAM's CORS filter says it varies by {@code Origin}, {@code Access-Control-Request-Method}
 * and {@code Access-Control-Request-Headers}, whether or not the request was a CORS request, as with Spring Framework 6
 * (HelixIAM 1.0). A shared cache must not hand one origin's response (with or without CORS headers) to another origin.
 * Spring Framework 7 only adds them when a CORS configuration applies to the request.
 */
class CorsVaryHeaderE2eTest extends AbstractE2eTest {

    private static final List<String> VARY = List.of("Origin", "Access-Control-Request-Method",
            "Access-Control-Request-Headers");

    @Test
    void discoveryJwksTokenAndPages_varyByTheCorsRequestHeaders() {
        final E2eHttp http = newBrowser();
        assertVaries(http.get("/realms/" + MASTER + "/.well-known/openid-configuration"));
        assertVaries(http.get("/realms/" + MASTER + "/.well-known/oauth-authorization-server"));
        assertVaries(http.get("/realms/" + MASTER + "/oauth2/jwks"));
        assertVaries(http.postForm("/realms/" + MASTER + "/oauth2/token",
                Map.of("grant_type", "client_credentials", "client_id", "nobody", "client_secret", "wrong")));
        assertVaries(http.get("/realms/" + MASTER + "/login"));
        assertVaries(http.get("/actuator/health"));
    }

    @Test
    void aCorsRequest_varies_andIsStillAnsweredByTheCorsFilter() {
        final E2eHttp.Response response = newBrowser().get("/realms/" + MASTER + "/.well-known/openid-configuration",
                "Origin", "https://not-a-registered-origin.example");
        assertVaries(response);
        assertThat(response.header("Access-Control-Allow-Origin")).isEmpty();
    }

    private static void assertVaries(final E2eHttp.Response response) {
        final List<String> vary = response.headers().allValues("Vary").stream()
                .flatMap(v -> java.util.Arrays.stream(v.split(","))).map(String::trim).toList();
        assertThat(vary).as("%s %s -> %s", response.method(), response.uri(), response.status())
                .containsAll(VARY).doesNotHaveDuplicates();
    }
}
