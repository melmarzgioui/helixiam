/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.net;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Outside dev, a request whose host (after trusted forwarded-header processing) is not this server's — the host of
 * IDP_BASE_URL or SP_BASE_URL, or one in HELIX_ALLOWED_HOSTS — is refused with 400 before anything (the
 * request-derived issuer, redirects, absolute URLs) is built from it. Probes keep working: the host may be the
 * address the connection arrived on (kubelet / Docker HEALTHCHECK), {@code localhost} from a loopback peer, and the
 * health endpoints accept any host.
 */
class HostAllowListFilterTest {

    private static HostAllowListFilter filter(final boolean enforce) {
        return HostAllowListFilter.of("https://idp.example.com", "https://console.example.com",
                "idp.internal, Auth.Example.ORG", enforce, Clock.systemUTC());
    }

    private static MockHttpServletRequest request(final String host, final String path) {
        final MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setServerName(host);
        request.setServerPort(8080);
        request.setRemoteAddr("198.51.100.20");
        request.setLocalAddr("10.42.0.17");
        request.setLocalPort(8080);
        return request;
    }

    private static int status(final HostAllowListFilter filter, final HttpServletRequest request) throws Exception {
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, response, chain);
        if (chain.getRequest() == null) {
            assertThat(response.getStatus()).isEqualTo(400);
            return 400;
        }
        return 200;
    }

    @Test
    void aForgedHost_is400() throws Exception {
        assertThat(status(filter(true), request("evil.example", "/realms/master/.well-known/openid-configuration")))
                .isEqualTo(400);
    }

    @Test
    void theServersOwnHosts_pass_caseInsensitive() throws Exception {
        final HostAllowListFilter filter = filter(true);
        assertThat(status(filter, request("idp.example.com", 443, "/realms/master/login"))).isEqualTo(200);
        assertThat(status(filter, request("IDP.example.com", 443, "/realms/master/login"))).isEqualTo(200);
        assertThat(status(filter, request("console.example.com", 443, "/admin/realms"))).isEqualTo(200);
        // HELIX_ALLOWED_HOSTS entries without a port accept any port.
        assertThat(status(filter, request("idp.internal", "/realms/master/protocol"))).isEqualTo(200);
        assertThat(status(filter, request("auth.example.org", "/realms/master/login"))).isEqualTo(200);
    }

    // --- the port is part of what the issuer echoes ------------------------------------------------------------

    private static MockHttpServletRequest request(final String host, final int port, final String path) {
        final MockHttpServletRequest request = request(host, path);
        request.setServerPort(port);
        return request;
    }

    @Test
    void aHostWithAnotherPortThanItsBaseUrl_is400() throws Exception {
        final HostAllowListFilter filter = HostAllowListFilter.of("http://localhost:8080", "http://console.local:8090",
                "", true, Clock.systemUTC());
        assertThat(status(filter, request("localhost", 8080, "/realms/master/login"))).isEqualTo(200);
        // Host: localhost:6666 would put :6666 into the request-derived issuer.
        assertThat(status(filter, request("localhost", 6666, "/realms/master/.well-known/openid-configuration")))
                .isEqualTo(400);
        assertThat(status(filter, request("console.local", 8090, "/admin/realms"))).isEqualTo(200);
        assertThat(status(filter, request("console.local", 8080, "/admin/realms"))).isEqualTo(400);
    }

    @Test
    void theSchemesDefaultPort_isTheBaseUrlsPortWhenItNamesNone() throws Exception {
        final HostAllowListFilter filter = filter(true); // https://idp.example.com → 443
        final MockHttpServletRequest https = request("idp.example.com", 443, "/realms/master/login");
        https.setScheme("https");
        https.setSecure(true);
        assertThat(status(filter, https)).isEqualTo(200);
        assertThat(status(filter, request("idp.example.com", 8443, "/realms/master/login"))).isEqualTo(400);
    }

    @Test
    void aHostWithoutAPort_isAccepted_sinceNoPortIsEchoed() throws Exception {
        // No port in Host: the container reports the scheme's default, which never appears in a built URL.
        final HostAllowListFilter filter = HostAllowListFilter.of("http://localhost:8080", "", "", true, Clock.systemUTC());
        assertThat(status(filter, request("localhost", 80, "/realms/master/login"))).isEqualTo(200);
    }

    @Test
    void anInvalidPort_is400() throws Exception {
        final HostAllowListFilter filter = filter(true);
        assertThat(status(filter, request("idp.internal", 0, "/realms/master/login"))).isEqualTo(400);
        assertThat(status(filter, request("idp.internal", 70000, "/realms/master/login"))).isEqualTo(400);
        assertThat(status(filter, request("idp.internal", -1, "/realms/master/login"))).isEqualTo(400);
    }

    @Test
    void anAllowedHostsEntryMayPinAPort() throws Exception {
        final HostAllowListFilter filter = HostAllowListFilter.of("https://idp.example.com", "",
                "helixiam.default.svc:8080, [fd00::1]:9000", true, Clock.systemUTC());
        assertThat(status(filter, request("helixiam.default.svc", 8080, "/realms/master/protocol"))).isEqualTo(200);
        assertThat(status(filter, request("helixiam.default.svc", 9999, "/realms/master/protocol"))).isEqualTo(400);
        assertThat(status(filter, request("[fd00::1]", 9000, "/realms/master/protocol"))).isEqualTo(200);
        assertThat(status(filter, request("[fd00::1]", 9001, "/realms/master/protocol"))).isEqualTo(400);
    }

    @Test
    void aLoopbackProbe_onAnotherPortThanTheConnections_is400_butHealthAnswersAnyway() throws Exception {
        final HostAllowListFilter filter = HostAllowListFilter.of("http://localhost:8080", "", "", true, Clock.systemUTC());
        final MockHttpServletRequest forged = request("localhost", 6666, "/realms/master/.well-known/openid-configuration");
        forged.setRemoteAddr("127.0.0.1");
        forged.setLocalPort(8080);
        assertThat(status(filter, forged)).isEqualTo(400);
        // curl from inside the container on the port the server listens on (here not the base URL's)
        final MockHttpServletRequest inside = request("localhost", 18080, "/realms/master/.well-known/openid-configuration");
        inside.setRemoteAddr("127.0.0.1");
        inside.setLocalPort(18080);
        assertThat(status(filter, inside)).isEqualTo(200);
        // kubelet: the pod IP on the container port
        final MockHttpServletRequest kubelet = request("10.42.0.17", 8080, "/actuator/prometheus");
        kubelet.setLocalPort(8080);
        assertThat(status(filter, kubelet)).isEqualTo(200);
        final MockHttpServletRequest kubeletOtherPort = request("10.42.0.17", 6666, "/actuator/prometheus");
        kubeletOtherPort.setLocalPort(8080);
        assertThat(status(filter, kubeletOtherPort)).isEqualTo(400);
        assertThat(status(filter, request("localhost", 6666, "/actuator/health/readiness"))).isEqualTo(200);
    }

    @Test
    void probes_keepWorking() throws Exception {
        final HostAllowListFilter filter = filter(true);
        // kubelet httpGet: Host is the pod IP — the address the connection arrived on.
        assertThat(status(filter, request("10.42.0.17", "/actuator/health/readiness"))).isEqualTo(200);
        assertThat(status(filter, request("10.42.0.17", "/actuator/prometheus"))).isEqualTo(200);
        // Docker HEALTHCHECK: curl http://127.0.0.1:8080/... from inside the container.
        final MockHttpServletRequest docker = request("127.0.0.1", "/actuator/health/readiness");
        docker.setRemoteAddr("127.0.0.1");
        docker.setLocalAddr("127.0.0.1");
        assertThat(status(filter, docker)).isEqualTo(200);
        // curl http://localhost:8080 from inside the container.
        final MockHttpServletRequest local = request("localhost", "/realms/master/.well-known/openid-configuration");
        local.setRemoteAddr("127.0.0.1");
        assertThat(status(filter, local)).isEqualTo(200);
        // A health check through a load balancer with its own host name.
        assertThat(status(filter, request("lb-health.internal", "/actuator/health"))).isEqualTo(200);
    }

    @Test
    void localhost_fromARemotePeer_isNotAllowed() throws Exception {
        assertThat(status(filter(true), request("localhost", "/realms/master/login"))).isEqualTo(400);
    }

    @Test
    void anIpThatIsNotTheLocalAddress_isNotAllowed() throws Exception {
        assertThat(status(filter(true), request("203.0.113.9", "/realms/master/login"))).isEqualTo(400);
    }

    @Test
    void inDev_nothingIsChecked() throws Exception {
        assertThat(status(filter(false), request("evil.example", "/realms/master/login"))).isEqualTo(200);
    }

    @Test
    void aTrustedProxysForwardedHost_isWhatIsChecked() throws Exception {
        final TrustedProxyForwardedHeaderFilter forwarded =
                new TrustedProxyForwardedHeaderFilter(new ClientIpResolver("10.0.0.0/8"));
        final MockHttpServletRequest viaProxy = request("helixiam.default.svc", "/realms/master/login");
        viaProxy.setRemoteAddr("10.1.2.3");
        viaProxy.addHeader("X-Forwarded-Host", "idp.example.com");
        viaProxy.addHeader("X-Forwarded-Proto", "https");
        final MockFilterChain outer = new MockFilterChain();
        forwarded.doFilter(viaProxy, new MockHttpServletResponse(), outer);

        assertThat(status(filter(true), (HttpServletRequest) outer.getRequest())).isEqualTo(200);
    }

    @Test
    void httpBehindAnHttpsIssuer_logsAnErrorAtMostOncePerMinute() throws Exception {
        final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-10-12T10:00:00Z"));
        final Clock clock = new Clock() {
            @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(final java.time.ZoneId zone) { return this; }
            @Override public Instant instant() { return now.get(); }
        };
        final HostAllowListFilter filter = HostAllowListFilter.of("https://idp.example.com", "", "", true, clock);

        // A TLS-terminating proxy that is not trusted forwards Host: idp.example.com (no port) over plain http.
        status(filter, request("idp.example.com", 80, "/realms/master/login"));
        status(filter, request("idp.example.com", 80, "/realms/master/login"));
        assertThat(filter.schemeErrorsLogged()).isEqualTo(1);
        now.set(now.get().plus(Duration.ofSeconds(61)));
        status(filter, request("idp.example.com", 80, "/realms/master/login"));
        assertThat(filter.schemeErrorsLogged()).isEqualTo(2);
        // Probes are plain http by nature and never trigger it.
        now.set(now.get().plus(Duration.ofSeconds(61)));
        status(filter, request("10.42.0.17", "/actuator/health/readiness"));
        assertThat(filter.schemeErrorsLogged()).isEqualTo(2);
        // An https request does not either.
        final MockHttpServletRequest secure = request("idp.example.com", 443, "/realms/master/login");
        secure.setScheme("https");
        secure.setSecure(true);
        status(filter, secure);
        assertThat(filter.schemeErrorsLogged()).isEqualTo(2);
    }
}
