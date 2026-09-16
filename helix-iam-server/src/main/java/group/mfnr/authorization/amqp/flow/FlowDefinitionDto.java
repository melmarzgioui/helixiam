package group.mfnr.authorization.amqp.flow;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM E8.5-S4: a realm's authentication flow as the console edits it (mirrors the subscriber copy).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FlowDefinitionDto(String realmId, String alias, boolean builtIn, List<FlowExecutionDto> executions) {
}
