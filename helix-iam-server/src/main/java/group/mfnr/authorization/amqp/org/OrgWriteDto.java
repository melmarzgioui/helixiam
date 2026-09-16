package group.mfnr.authorization.amqp.org;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM Organizations: create/update payload for an organization (mirrors the subscriber copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OrgWriteDto(String realmId, String orgId, String name, String displayName, List<String> domains,
                          boolean enabled) {
}
