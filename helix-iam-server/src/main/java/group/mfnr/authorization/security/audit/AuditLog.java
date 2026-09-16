package group.mfnr.authorization.security.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import group.mfnr.authorization.amqp.audit.AuditLogPublisher;
import group.mfnr.authorization.amqp.audit.AuditRecord;
import group.mfnr.authorization.security.webhook.WebhookDispatcher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Helix IAM E8.5-S4 (Events): the single entry point for emitting an audit event. Each event is
 * serialized to one flat JSON line and (a) logged to the dedicated {@code helix.audit} logger — which a
 * SIEM scrapes from stdout, (b) handed to {@link HttpAuditForwarder} for optional push to a SIEM webhook,
 * and (B3) persisted to the searchable in-product audit log via {@link AuditLogPublisher} (off the request
 * thread, best-effort). Emission is gated by {@link HelixAuditProperties#ships(String)}.
 */
@Component
public class AuditLog {

    /** Dedicated logger; routed to a pure-JSON stdout appender by log4j2-spring.xml. */
    private static final Logger AUDIT = LogManager.getLogger("helix.audit");
    private static final Logger LOG = LogManager.getLogger(AuditLog.class);

    private final ObjectMapper mapper;
    private final HelixAuditProperties props;
    private final HttpAuditForwarder forwarder;
    private final ObjectProvider<AuditLogPublisher> auditLogPublisher;
    private final ObjectProvider<WebhookDispatcher> webhookDispatcher;
    private final ExecutorService persistExecutor;

    /** Back-compat (tests): no persistence publisher / webhook dispatcher. */
    public AuditLog(final ObjectMapper mapper, final HelixAuditProperties props, final HttpAuditForwarder forwarder) {
        this(mapper, props, forwarder, null, null);
    }

    @Autowired
    public AuditLog(final ObjectMapper mapper, final HelixAuditProperties props, final HttpAuditForwarder forwarder,
                    final ObjectProvider<AuditLogPublisher> auditLogPublisher,
                    final ObjectProvider<WebhookDispatcher> webhookDispatcher) {
        this.mapper = mapper;
        this.props = props;
        this.forwarder = forwarder;
        this.auditLogPublisher = auditLogPublisher;
        this.webhookDispatcher = webhookDispatcher;
        this.persistExecutor = Executors.newSingleThreadExecutor(r -> {
            final Thread t = new Thread(r, "audit-persist");
            t.setDaemon(true);
            return t;
        });
    }

    /** Emits an audit event to stdout, the SIEM webhook, and the searchable audit store; never throws. */
    public void emit(final AuditEvent event) {
        if (!props.ships(event.category())) {
            return;
        }
        final String json = toJson(event);
        if (json == null) {
            return;
        }
        AUDIT.info(json);
        forwarder.forward(json);
        persist(event);
        // B6: fan the event out to per-realm subscribed webhooks (best-effort, off-thread).
        if (webhookDispatcher != null) {
            final WebhookDispatcher dispatcher = webhookDispatcher.getIfAvailable();
            if (dispatcher != null) {
                dispatcher.dispatch(event, json);
            }
        }
    }

    /** B3: persist to the queryable store off the request thread (best-effort — never blocks/throws on login). */
    private void persist(final AuditEvent event) {
        if (auditLogPublisher == null || event.realm() == null || event.realm().isBlank()) {
            return; // not wired (tests), or no realm to scope the search by
        }
        final AuditLogPublisher publisher = auditLogPublisher.getIfAvailable();
        if (publisher == null) {
            return;
        }
        final String detail = event.detail() == null ? null : toJsonSafe(event.detail());
        final AuditRecord record = new AuditRecord(event.ts(), event.kind(), event.category(), event.type(),
                event.realm(), event.actor(), event.sourceIp(), event.resourceType(), event.resourceId(),
                event.outcome(), detail);
        persistExecutor.execute(() -> {
            try {
                publisher.record(record);
            } catch (final RuntimeException e) {
                LOG.debug("Audit persist failed (event still on stdout/SIEM): {}", e.getMessage());
            }
        });
    }

    private String toJsonSafe(final Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (final JsonProcessingException e) {
            return null;
        }
    }

    /** Serializes an event to a single-line JSON string, or {@code null} if serialization fails. */
    String toJson(final AuditEvent event) {
        try {
            return mapper.writeValueAsString(event);
        } catch (final JsonProcessingException e) {
            LOG.warn("Could not serialize audit event {}: {}", event.type(), e.getMessage());
            return null;
        }
    }
}
