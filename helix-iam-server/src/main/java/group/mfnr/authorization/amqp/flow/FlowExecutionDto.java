package group.mfnr.authorization.amqp.flow;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/**
 * Helix IAM E8.5-S4: one node of an editable authentication flow (mirrors the subscriber's domain copy).
 * parentId == null at top level; ordering within a parent is by {@code priority}. {@code config} carries
 * per-execution admin settings (e.g. an identity-provider redirect's alias + mode); empty for most steps.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FlowExecutionDto(String executionId, String parentId, String authenticatorId,
                               String requirement, boolean condition, int priority,
                               Map<String, String> config) {

    /** Back-compat: a step with no per-execution config. */
    public FlowExecutionDto(final String executionId, final String parentId, final String authenticatorId,
                            final String requirement, final boolean condition, final int priority) {
        this(executionId, parentId, authenticatorId, requirement, condition, priority, Map.of());
    }
}
