package group.mfnr.authorization.amqp.scope;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Helix IAM E8.5: publisher-side view of a client scope for the list/table (mirrors the subscriber copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientScopeDto(String realmId, String scopeId, String name, String description,
                             long claimCount, List<String> claimPreview) {
}
