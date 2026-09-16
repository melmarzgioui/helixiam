package group.mfnr.authorization.session;

import group.mfnr.authorization.amqp.httpsession.HttpSessionRecord;
import group.mfnr.authorization.amqp.httpsession.HttpSessionStorePublisher;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.MapSession;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM (Q3): the queue-backed Spring {@code SessionRepository} round-trips a login session (attributes +
 * SecurityContext) through the subscriber over AMQP, indexes it by principal for the logout cascade, and
 * honours expiry. Verified against an in-memory fake store.
 */
class QueueIndexedSessionRepositoryTest {

    private static final class FakeStore implements HttpSessionStorePublisher {
        final Map<String, HttpSessionRecord> byId = new LinkedHashMap<>();

        @Override public Boolean save(final HttpSessionRecord r) { byId.put(r.sessionId(), r); return true; }
        @Override public HttpSessionRecord findById(final String id) { return byId.get(id); }
        @Override public Boolean deleteById(final String id) { byId.remove(id); return true; }
        @Override public List<HttpSessionRecord> findByPrincipal(final String principal) {
            final List<HttpSessionRecord> out = new ArrayList<>();
            byId.values().forEach(r -> { if (principal.equals(r.principalName())) out.add(r); });
            return out;
        }
        @Override public Integer deleteByPrincipal(final String principal) {
            final List<HttpSessionRecord> hits = findByPrincipal(principal);
            hits.forEach(r -> byId.remove(r.sessionId()));
            return hits.size();
        }
    }

    @Test
    void save_thenFindById_roundTripsAttributes() {
        final FakeStore store = new FakeStore();
        final QueueIndexedSessionRepository repo = new QueueIndexedSessionRepository(store, Duration.ofMinutes(30));

        final MapSession s = repo.createSession();
        s.setAttribute("hello", "world");
        repo.save(s);

        final MapSession loaded = repo.findById(s.getId());
        assertThat(loaded).isNotNull();
        assertThat(loaded.<String>getAttribute("hello")).isEqualTo("world");
    }

    @Test
    void save_indexesByPrincipal_forLogoutCascade() {
        final FakeStore store = new FakeStore();
        final QueueIndexedSessionRepository repo = new QueueIndexedSessionRepository(store, Duration.ofMinutes(30));

        final MapSession s = repo.createSession();
        final SecurityContextImpl ctx = new SecurityContextImpl(new UsernamePasswordAuthenticationToken(
                "alice", "n/a", AuthorityUtils.createAuthorityList("ROLE_USER")));
        s.setAttribute("SPRING_SECURITY_CONTEXT", ctx);
        repo.save(s);

        final Map<String, MapSession> byPrincipal = repo.findByIndexNameAndIndexValue(
                FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, "alice");
        assertThat(byPrincipal).containsKey(s.getId());
    }

    @Test
    void findById_returnsNull_andDeletes_whenExpired() {
        final FakeStore store = new FakeStore();
        final QueueIndexedSessionRepository repo = new QueueIndexedSessionRepository(store, Duration.ofMinutes(30));
        // Persist a record that is already expired (last access far in the past, 1s timeout).
        store.byId.put("old", new HttpSessionRecord("old", "alice", null,
                0L, 1000L, 1, 2000L));

        assertThat(repo.findById("old")).isNull();
        assertThat(store.byId).doesNotContainKey("old"); // expired → deleted
    }

    @Test
    void deleteById_removes() {
        final FakeStore store = new FakeStore();
        final QueueIndexedSessionRepository repo = new QueueIndexedSessionRepository(store, Duration.ofMinutes(30));
        final MapSession s = repo.createSession();
        repo.save(s);

        repo.deleteById(s.getId());

        assertThat(store.byId).doesNotContainKey(s.getId());
    }
}
