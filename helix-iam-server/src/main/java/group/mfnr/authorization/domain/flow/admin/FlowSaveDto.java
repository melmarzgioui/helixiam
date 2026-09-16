package group.mfnr.authorization.domain.flow.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM E8.5-S4: the editor's save payload — the realm + flow alias and the full replacement set of
 * executions. Saving replaces the flow's executions wholesale. Mirrors the publisher copy.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FlowSaveDto(String realmId, String alias, List<FlowExecutionDto> executions) {
}
