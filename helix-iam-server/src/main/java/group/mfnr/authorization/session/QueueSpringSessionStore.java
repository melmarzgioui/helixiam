package group.mfnr.authorization.session;

import group.mfnr.authorization.amqp.httpsession.HttpSessionStorePublisher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Helix IAM (Q3): deletes a principal's HTTP login sessions from the queue-backed store (subscriber), for the
 * cascading logout — the queue counterpart of {@code JdbcSpringSessionStore}. Selected when
 * {@code helix.iam.session-store=queue}.
 */
public class QueueSpringSessionStore implements SpringSessionStore {

    private static final Logger LOG = LogManager.getLogger(QueueSpringSessionStore.class);

    private final HttpSessionStorePublisher store;

    public QueueSpringSessionStore(final HttpSessionStorePublisher store) {
        this.store = store;
    }

    @Override
    public int deleteByPrincipal(final String principalName) {
        try {
            final Integer removed = store.deleteByPrincipal(principalName);
            return removed == null ? 0 : removed;
        } catch (final RuntimeException e) {
            LOG.debug("queue session delete for {} skipped: {}", principalName, e.getMessage());
            return 0;
        }
    }
}
