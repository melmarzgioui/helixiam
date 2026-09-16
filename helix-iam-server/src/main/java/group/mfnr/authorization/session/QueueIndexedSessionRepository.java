package group.mfnr.authorization.session;

import group.mfnr.authorization.amqp.httpsession.HttpSessionRecord;
import group.mfnr.authorization.amqp.httpsession.HttpSessionStorePublisher;
import group.mfnr.authorization.security.SessionBlobs;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.IndexResolver;
import org.springframework.session.MapSession;
import org.springframework.session.PrincipalNameIndexResolver;
import org.springframework.session.Session;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helix IAM (Q3): a Spring Session {@link FindByIndexNameSessionRepository} that persists HTTP login sessions
 * to the subscriber over AMQP, so the publisher needs no datasource. The session's attributes (incl. the
 * SecurityContext) are serialized to an opaque blob ({@link SessionBlobs}); the principal is indexed so a
 * logout can find every session for a user. Selected when {@code helix.iam.session-store=queue}.
 */
public class QueueIndexedSessionRepository implements FindByIndexNameSessionRepository<MapSession> {

    private final HttpSessionStorePublisher store;
    private final IndexResolver<Session> indexResolver = new PrincipalNameIndexResolver<>();
    private final Duration defaultMaxInactive;

    public QueueIndexedSessionRepository(final HttpSessionStorePublisher store, final Duration defaultMaxInactive) {
        this.store = store;
        this.defaultMaxInactive = defaultMaxInactive;
    }

    @Override
    public MapSession createSession() {
        final MapSession session = new MapSession();
        session.setMaxInactiveInterval(defaultMaxInactive);
        return session;
    }

    @Override
    public void save(final MapSession session) {
        final Map<String, Object> attributes = new HashMap<>();
        for (final String name : session.getAttributeNames()) {
            attributes.put(name, session.getAttribute(name));
        }
        final long expiry = session.getMaxInactiveInterval().isNegative() || session.getMaxInactiveInterval().isZero()
                ? Long.MAX_VALUE
                : session.getLastAccessedTime().plus(session.getMaxInactiveInterval()).toEpochMilli();
        store.save(new HttpSessionRecord(session.getId(), principalOf(session), SessionBlobs.serialize(attributes),
                session.getCreationTime().toEpochMilli(), session.getLastAccessedTime().toEpochMilli(),
                (int) session.getMaxInactiveInterval().getSeconds(), expiry));
    }

    @Override
    public MapSession findById(final String id) {
        final MapSession session = toSession(store.findById(id));
        if (session == null) {
            return null;
        }
        if (session.isExpired()) {
            store.deleteById(id);
            return null;
        }
        return session;
    }

    @Override
    public void deleteById(final String id) {
        store.deleteById(id);
    }

    @Override
    public Map<String, MapSession> findByIndexNameAndIndexValue(final String indexName, final String indexValue) {
        if (!PRINCIPAL_NAME_INDEX_NAME.equals(indexName) || indexValue == null) {
            return Map.of();
        }
        final Map<String, MapSession> result = new LinkedHashMap<>();
        for (final HttpSessionRecord r : store.findByPrincipal(indexValue)) {
            final MapSession s = toSession(r);
            if (s != null && !s.isExpired()) {
                result.put(s.getId(), s);
            }
        }
        return result;
    }

    private MapSession toSession(final HttpSessionRecord r) {
        if (r == null) {
            return null;
        }
        final MapSession session = new MapSession(r.sessionId());
        if (r.creationTime() != null) {
            session.setCreationTime(Instant.ofEpochMilli(r.creationTime()));
        }
        if (r.lastAccessTime() != null) {
            session.setLastAccessedTime(Instant.ofEpochMilli(r.lastAccessTime()));
        }
        session.setMaxInactiveInterval(Duration.ofSeconds(r.maxInactiveSeconds() == null ? 1800 : r.maxInactiveSeconds()));
        SessionBlobs.deserialize(r.blob()).forEach(session::setAttribute);
        return session;
    }

    private String principalOf(final Session session) {
        final Map<String, String> indexes = indexResolver.resolveIndexesFor(session);
        return indexes.get(PRINCIPAL_NAME_INDEX_NAME);
    }
}
