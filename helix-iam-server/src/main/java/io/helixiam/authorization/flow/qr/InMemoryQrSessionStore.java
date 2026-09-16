package io.helixiam.authorization.flow.qr;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Helix IAM E4.2: default in-process {@link QrSessionStore} (single-instance / dev). For horizontally
 * scaled deployments a Redis-backed store replaces this (declared with {@code @ConditionalOnMissingBean}
 * in FlowConfig). Sessions are short-lived (5-minute TTL) and removed on consume, so growth is bounded.
 */
public class InMemoryQrSessionStore implements QrSessionStore {

    private final ConcurrentMap<String, QrSession> sessions = new ConcurrentHashMap<>();

    @Override
    public void save(final QrSession session) {
        sessions.put(session.id(), session);
    }

    @Override
    public Optional<QrSession> find(final String id) {
        return Optional.ofNullable(sessions.get(id));
    }

    @Override
    public void remove(final String id) {
        sessions.remove(id);
    }
}
