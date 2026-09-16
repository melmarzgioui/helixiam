package group.mfnr.authorization.domain.flow.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM (named flows): create a new named flow, optionally copying an existing flow's steps. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FlowCreateDto(String realmId, String alias, String copyFromAlias) {
}
