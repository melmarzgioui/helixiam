package io.helixiam.authorization.security.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Helix IAM E8.5-S4 (Events): the read-only config view must surface status without ever leaking the
 * SIEM auth secret.
 */
class AuditConfigDtoTest {

    @Test
    void neverExposesTheAuthSecret_butReportsItIsConfigured() throws Exception {
        final HelixAuditProperties props = new HelixAuditProperties();
        props.getHttp().setUrl("https://siem.gov.nl/collector");
        props.getHttp().setAuthHeader("Splunk super-secret-token-value");

        final AuditConfigDto dto = AuditConfigDto.from(props);
        final String json = new ObjectMapper().writeValueAsString(dto);

        assertFalse(json.contains("super-secret-token-value"), "auth secret must never be serialized");
        assertTrue(dto.authConfigured());
        assertTrue(dto.httpConfigured());
        assertEquals("https://siem.gov.nl/collector", dto.httpUrl());
        assertTrue(dto.transports().contains("stdout"));
        assertTrue(dto.transports().contains("http"));
    }

    @Test
    void stdoutOnly_whenNoWebhookConfigured() {
        final AuditConfigDto dto = AuditConfigDto.from(new HelixAuditProperties());
        assertFalse(dto.httpConfigured());
        assertFalse(dto.authConfigured());
        assertEquals(1, dto.transports().size());
        assertTrue(dto.transports().contains("stdout"));
    }
}
