package group.mfnr.authorization.domain.flow.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM (named flows): a realm flow as it appears in the editor's flow picker — alias + whether it is
 * the built-in browser flow (which cannot be renamed or deleted). Mirrors the publisher copy.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FlowSummaryDto(String realmId, String alias, boolean builtIn) {
}
