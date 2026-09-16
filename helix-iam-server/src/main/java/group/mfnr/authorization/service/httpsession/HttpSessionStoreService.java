package group.mfnr.authorization.service.httpsession;

import group.mfnr.authorization.domain.httpsession.HelixHttpSession;
import group.mfnr.authorization.domain.httpsession.admin.HttpSessionRecord;
import group.mfnr.authorization.repository.httpsession.HelixHttpSessionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Helix IAM (Q3): the subscriber-owned store of Spring Session HTTP login sessions, reached over AMQP so the
 * publisher needs no datasource. Opaque blob (serialized attributes) keyed by session id, indexed by principal
 * for the logout cascade.
 */
@Service
public class HttpSessionStoreService {

    private final HelixHttpSessionRepository sessions;

    public HttpSessionStoreService(final HelixHttpSessionRepository sessions) {
        this.sessions = sessions;
    }

    @Transactional
    public Boolean save(final HttpSessionRecord r) {
        final HelixHttpSession e = sessions.findById(r.sessionId()).orElseGet(HelixHttpSession::new);
        e.setSessionId(r.sessionId());
        e.setPrincipalName(r.principalName());
        e.setBlob(r.blob());
        e.setCreationTime(r.creationTime());
        e.setLastAccessTime(r.lastAccessTime());
        e.setMaxInactiveSeconds(r.maxInactiveSeconds());
        e.setExpiryTime(r.expiryTime());
        sessions.save(e);
        return true;
    }

    public HttpSessionRecord findById(final String sessionId) {
        return sessions.findById(sessionId).map(HttpSessionStoreService::toRecord).orElse(null);
    }

    @Transactional
    public Boolean deleteById(final String sessionId) {
        sessions.findById(sessionId).ifPresent(sessions::delete);
        return true;
    }

    public List<HttpSessionRecord> findByPrincipal(final String principalName) {
        return sessions.findByPrincipalName(principalName).stream().map(HttpSessionStoreService::toRecord).toList();
    }

    @Transactional
    public Integer deleteByPrincipal(final String principalName) {
        final List<HelixHttpSession> rows = sessions.findByPrincipalName(principalName);
        sessions.deleteAll(rows);
        return rows.size();
    }

    private static HttpSessionRecord toRecord(final HelixHttpSession e) {
        return new HttpSessionRecord(e.getSessionId(), e.getPrincipalName(), e.getBlob(), e.getCreationTime(),
                e.getLastAccessTime(), e.getMaxInactiveSeconds(), e.getExpiryTime());
    }
}
