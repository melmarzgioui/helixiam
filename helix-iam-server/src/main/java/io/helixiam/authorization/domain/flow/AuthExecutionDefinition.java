package io.helixiam.authorization.domain.flow;

import java.io.Serializable;
import java.util.Map;

/**
 * Helix IAM E2.5: a flat, transport-friendly row of a persisted flow (subscriber copy; matches
 * the publisher's class field-for-field so JSON marshalling round-trips it over AMQP).
 */
public class AuthExecutionDefinition implements Serializable {

    private static final long serialVersionUID = 1L;

    private String id;
    private String parentId;
    private String authenticatorId;
    private String requirement;
    private boolean condition;
    private int priority;
    private Map<String, String> config; // per-execution admin config (from the flow editor)

    public AuthExecutionDefinition() {
    }

    public AuthExecutionDefinition(final String id, final String parentId, final String authenticatorId,
                                   final String requirement, final boolean condition, final int priority) {
        this(id, parentId, authenticatorId, requirement, condition, priority, Map.of());
    }

    public AuthExecutionDefinition(final String id, final String parentId, final String authenticatorId,
                                   final String requirement, final boolean condition, final int priority,
                                   final Map<String, String> config) {
        this.id = id;
        this.parentId = parentId;
        this.authenticatorId = authenticatorId;
        this.requirement = requirement;
        this.condition = condition;
        this.priority = priority;
        this.config = config;
    }

    public String getId() {
        return id;
    }

    public void setId(final String id) {
        this.id = id;
    }

    public String getParentId() {
        return parentId;
    }

    public void setParentId(final String parentId) {
        this.parentId = parentId;
    }

    public String getAuthenticatorId() {
        return authenticatorId;
    }

    public void setAuthenticatorId(final String authenticatorId) {
        this.authenticatorId = authenticatorId;
    }

    public String getRequirement() {
        return requirement;
    }

    public void setRequirement(final String requirement) {
        this.requirement = requirement;
    }

    public boolean isCondition() {
        return condition;
    }

    public void setCondition(final boolean condition) {
        this.condition = condition;
    }

    public int getPriority() {
        return priority;
    }

    public void setPriority(final int priority) {
        this.priority = priority;
    }

    public Map<String, String> getConfig() {
        return config;
    }

    public void setConfig(final Map<String, String> config) {
        this.config = config;
    }
}
