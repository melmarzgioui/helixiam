package group.mfnr.authorization.flow;

import java.util.List;
import java.util.Optional;

/**
 * Helix IAM E2: an authentication flow — an ordered list of {@link AuthExecution executions}
 * (authenticators and sub-flows). Pure data, realm-scoped, editable from the admin console.
 */
public final class AuthFlow {

    private final String id;
    private final List<AuthExecution> executions;

    private AuthFlow(final String id, final List<AuthExecution> executions) {
        this.id = id;
        this.executions = List.copyOf(executions);
    }

    public static AuthFlow of(final String id, final AuthExecution... executions) {
        return new AuthFlow(id, List.of(executions));
    }

    public String id() {
        return id;
    }

    public List<AuthExecution> executions() {
        return executions;
    }

    /** Finds an execution by id anywhere in this flow, descending into sub-flows. */
    public Optional<AuthExecution> findExecution(final String executionId) {
        for (final AuthExecution execution : executions) {
            if (execution.id().equals(executionId)) {
                return Optional.of(execution);
            }
            if (execution.isSubFlow()) {
                final Optional<AuthExecution> nested = execution.subFlow().findExecution(executionId);
                if (nested.isPresent()) {
                    return nested;
                }
            }
        }
        return Optional.empty();
    }
}
