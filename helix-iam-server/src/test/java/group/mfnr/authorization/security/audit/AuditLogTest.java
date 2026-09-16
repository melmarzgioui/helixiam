package group.mfnr.authorization.security.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Helix IAM E8.5-S4 (Events): the audit emitter serializes to one flat JSON line and forwards only when
 * audit is enabled and the event's category is shipped.
 */
class AuditLogTest {

    private HelixAuditProperties props;
    private HttpAuditForwarder forwarder;
    private AuditLog auditLog;

    private AuditEvent sampleAdmin() {
        return AuditEvent.admin("2026-06-26T19:10:21Z", "USER_CREATE", "gov", "admin-api", "172.18.0.1", "user", "u-1", "SUCCESS");
    }

    @BeforeEach
    void setUp() {
        props = new HelixAuditProperties();
        forwarder = mock(HttpAuditForwarder.class);
        auditLog = new AuditLog(new ObjectMapper(), props, forwarder);
    }

    @Test
    void serializesToSingleLineJsonWithEveryField() {
        final String json = auditLog.toJson(sampleAdmin());

        assertFalse(json.contains("\n"), "audit line must be single-line");
        assertTrue(json.contains("\"kind\":\"audit\""), json);
        assertTrue(json.contains("\"category\":\"ADMIN\""), json);
        assertTrue(json.contains("\"type\":\"USER_CREATE\""), json);
        assertTrue(json.contains("\"realm\":\"gov\""), json);
        assertTrue(json.contains("\"actor\":\"admin-api\""), json);
        assertTrue(json.contains("\"sourceIp\":\"172.18.0.1\""), json);
        assertTrue(json.contains("\"resourceType\":\"user\""), json);
        assertTrue(json.contains("\"resourceId\":\"u-1\""), json);
        assertTrue(json.contains("\"outcome\":\"SUCCESS\""), json);
    }

    @Test
    void forwardsWhenEnabledAndCategoryShipped() {
        auditLog.emit(sampleAdmin());
        verify(forwarder).forward(anyString());
    }

    @Test
    void doesNotForwardWhenAuditDisabled() {
        props.setEnabled(false);
        auditLog.emit(sampleAdmin());
        verify(forwarder, never()).forward(anyString());
    }

    @Test
    void doesNotForwardWhenCategoryNotShipped() {
        props.setCategories(List.of(AuditEvent.AUTHN)); // ADMIN excluded
        auditLog.emit(sampleAdmin());
        verify(forwarder, never()).forward(anyString());
    }

    @Test
    void omitsNullResourceFieldsForAuthnEvents() {
        final String json = auditLog.toJson(
                AuditEvent.authn("2026-06-26T19:10:21Z", "LOGIN_FAILURE", "gov", "alice", "10.0.0.1", "FAILURE", null));
        assertFalse(json.contains("resourceType"), json);
        assertFalse(json.contains("\"detail\""), json);
        assertEquals(true, json.contains("\"type\":\"LOGIN_FAILURE\""));
    }
}
