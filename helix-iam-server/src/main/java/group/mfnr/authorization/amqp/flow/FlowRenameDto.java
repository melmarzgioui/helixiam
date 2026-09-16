package group.mfnr.authorization.amqp.flow;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM (named flows): rename a non-built-in flow. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FlowRenameDto(String realmId, String alias, String newAlias) {
}
