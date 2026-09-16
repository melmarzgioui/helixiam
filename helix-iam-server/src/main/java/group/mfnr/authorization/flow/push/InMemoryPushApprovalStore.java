package group.mfnr.authorization.flow.push;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Helix IAM E4.3: default in-process {@link PushApprovalStore} (single-instance / dev). A Redis-backed
 * store replaces it for horizontal scale (declared with {@code @ConditionalOnMissingBean} in FlowConfig).
 * Approvals are short-lived (2-minute TTL) and removed on consume, so growth is bounded.
 */
public class InMemoryPushApprovalStore implements PushApprovalStore {

    private final ConcurrentMap<String, PushApproval> approvals = new ConcurrentHashMap<>();

    @Override
    public void save(final PushApproval approval) {
        approvals.put(approval.id(), approval);
    }

    @Override
    public Optional<PushApproval> find(final String id) {
        return Optional.ofNullable(approvals.get(id));
    }

    @Override
    public void remove(final String id) {
        approvals.remove(id);
    }
}
