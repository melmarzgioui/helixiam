package group.mfnr.authorization.domain.flow.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM (named flows): a reference to one realm flow by alias (get / delete). Mirrors the publisher copy. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FlowRefDto(String realmId, String alias) {
}
