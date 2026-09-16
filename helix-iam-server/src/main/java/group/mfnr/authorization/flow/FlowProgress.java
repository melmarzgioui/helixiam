package group.mfnr.authorization.flow;

/**
 * Helix IAM E2.4: the result of advancing a flow — either a CHALLENGE the runtime must render
 * (a view + the execution awaiting input), or the flow has COMPLETED (with the authenticated
 * user) or FAILED.
 */
public final class FlowProgress {

    public enum Type {CHALLENGE, COMPLETED, FAILED}

    private final Type type;
    private final String view;
    private final String executionId;
    private final String userId;

    private FlowProgress(final Type type, final String view, final String executionId, final String userId) {
        this.type = type;
        this.view = view;
        this.executionId = executionId;
        this.userId = userId;
    }

    public static FlowProgress challenge(final String view, final String executionId) {
        return new FlowProgress(Type.CHALLENGE, view, executionId, null);
    }

    public static FlowProgress completed(final String userId) {
        return new FlowProgress(Type.COMPLETED, null, null, userId);
    }

    public static FlowProgress failed() {
        return new FlowProgress(Type.FAILED, null, null, null);
    }

    public Type type() {
        return type;
    }

    public String view() {
        return view;
    }

    public String executionId() {
        return executionId;
    }

    public String userId() {
        return userId;
    }
}
