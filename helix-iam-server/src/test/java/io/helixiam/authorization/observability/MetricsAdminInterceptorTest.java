package io.helixiam.authorization.observability;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class MetricsAdminInterceptorTest {

    private MeterRegistry registry;
    private MetricsAdminInterceptor interceptor;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        interceptor = new MetricsAdminInterceptor(new HelixMetrics(registry));
    }

    private double count(final String... tags) {
        var search = registry.find(HelixMetrics.ADMIN_WRITE_TOTAL);
        for (int i = 0; i + 1 < tags.length; i += 2) {
            search = search.tag(tags[i], tags[i + 1]);
        }
        var counter = search.counter();
        return counter == null ? -1d : counter.count();
    }

    @Test
    void metersMutatingRequest_withRealmFromPath() {
        final MockHttpServletRequest req = new MockHttpServletRequest("POST", "/admin/realms/master/clients");
        final MockHttpServletResponse res = new MockHttpServletResponse();
        res.setStatus(201);

        interceptor.afterCompletion(req, res, new Object(), null);

        assertThat(count("realm", "master", "method", "POST", "outcome", "success")).isEqualTo(1d);
    }

    @Test
    void ignoresReads() {
        final MockHttpServletRequest req = new MockHttpServletRequest("GET", "/admin/realms/master/clients");
        final MockHttpServletResponse res = new MockHttpServletResponse();
        res.setStatus(200);

        interceptor.afterCompletion(req, res, new Object(), null);

        assertThat(registry.find(HelixMetrics.ADMIN_WRITE_TOTAL).counters()).isEmpty();
    }

    @Test
    void mapsStatusToOutcome_deniedAndFailure() {
        final MockHttpServletRequest denied = new MockHttpServletRequest("DELETE", "/admin/realms/master/users/u1");
        final MockHttpServletResponse deniedRes = new MockHttpServletResponse();
        deniedRes.setStatus(403);
        interceptor.afterCompletion(denied, deniedRes, new Object(), null);

        final MockHttpServletRequest failed = new MockHttpServletRequest("PUT", "/admin/realms/master/settings");
        final MockHttpServletResponse failedRes = new MockHttpServletResponse();
        failedRes.setStatus(500);
        interceptor.afterCompletion(failed, failedRes, new Object(), null);

        assertThat(count("realm", "master", "method", "DELETE", "outcome", "denied")).isEqualTo(1d);
        assertThat(count("realm", "master", "method", "PUT", "outcome", "failure")).isEqualTo(1d);
    }

    @Test
    void exceptionWithSuccessStatus_recordedAsFailure() {
        final MockHttpServletRequest req = new MockHttpServletRequest("POST", "/admin/realms/master/clients");
        final MockHttpServletResponse res = new MockHttpServletResponse();
        res.setStatus(200);

        interceptor.afterCompletion(req, res, new Object(), new RuntimeException("boom"));

        assertThat(count("realm", "master", "method", "POST", "outcome", "failure")).isEqualTo(1d);
    }

    @Test
    void nonRealmAdminPath_usesUnknownRealm() {
        final MockHttpServletRequest req = new MockHttpServletRequest("POST", "/admin/metrics/whatever");
        final MockHttpServletResponse res = new MockHttpServletResponse();
        res.setStatus(200);

        interceptor.afterCompletion(req, res, new Object(), null);

        assertThat(count("realm", "unknown", "method", "POST", "outcome", "success")).isEqualTo(1d);
    }
}
