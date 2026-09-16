package io.helixiam.authorization.amqp.flow;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM E8.5-S4: the editor's save payload — realm + flow alias and the full replacement execution
 * set (mirrors the subscriber copy).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FlowSaveDto(String realmId, String alias, List<FlowExecutionDto> executions) {
}
