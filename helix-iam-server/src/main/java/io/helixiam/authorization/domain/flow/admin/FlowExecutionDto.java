package io.helixiam.authorization.domain.flow.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/**
 * Helix IAM E8.5-S4: one node of an editable authentication flow — a leaf authenticator, a condition,
 * or a sub-flow (parentId == null at top level; children point at their parent). Ordering within a
 * parent is by {@code priority}. {@code config} carries per-execution admin settings (e.g. an
 * identity-provider redirect's alias + mode). Mirrors the publisher's {@code amqp.flow.FlowExecutionDto}.
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
