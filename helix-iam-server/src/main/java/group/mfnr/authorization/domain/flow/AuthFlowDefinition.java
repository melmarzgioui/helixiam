package group.mfnr.authorization.domain.flow;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Helix IAM E2.5: a realm's persisted authentication flow as a flat list of executions
 * (subscriber copy; matches the publisher's class so JSON marshalling round-trips it).
 */
public class AuthFlowDefinition implements Serializable {

    private static final long serialVersionUID = 1L;

    private String alias;
    private String realmId;
    private List<AuthExecutionDefinition> executions = new ArrayList<>();

    public AuthFlowDefinition() {
    }

    public AuthFlowDefinition(final String alias, final String realmId,
                              final List<AuthExecutionDefinition> executions) {
        this.alias = alias;
        this.realmId = realmId;
        this.executions = executions == null ? new ArrayList<>() : executions;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(final String alias) {
        this.alias = alias;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(final String realmId) {
        this.realmId = realmId;
    }

    public List<AuthExecutionDefinition> getExecutions() {
        return executions;
    }

    public void setExecutions(final List<AuthExecutionDefinition> executions) {
        this.executions = executions;
    }
}
