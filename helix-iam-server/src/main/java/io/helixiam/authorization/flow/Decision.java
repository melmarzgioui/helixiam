package io.helixiam.authorization.flow;

/**
 * Helix IAM E2: the engine's verdict for a flow given the outcomes so far — either run the
 * next authenticator ({@link Kind#RUN} with its execution id), or the flow as a whole has
 * {@link Kind#SUCCESS succeeded} or {@link Kind#FAILURE failed}.
 */
public final class Decision {

    public enum Kind {RUN, SUCCESS, FAILURE}

    private final Kind kind;
    private final String executionId;

    private Decision(final Kind kind, final String executionId) {
        this.kind = kind;
        this.executionId = executionId;
    }

    public static Decision run(final String executionId) {
        return new Decision(Kind.RUN, executionId);
    }

    public static Decision success() {
        return new Decision(Kind.SUCCESS, null);
    }

    public static Decision failure() {
        return new Decision(Kind.FAILURE, null);
    }

    public Kind kind() {
        return kind;
    }

    /** The execution to run next; only meaningful when {@link #kind()} is {@link Kind#RUN}. */
    public String executionId() {
        return executionId;
    }

    @Override
    public String toString() {
        return kind == Kind.RUN ? "RUN(" + executionId + ")" : kind.name();
    }
}
