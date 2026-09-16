package group.mfnr.authorization.amqp.scope;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM E8.5: identifies a scope (and optionally a claim) for detail/delete/map ops. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScopeRef(String realmId, String scopeId, String claimId) {
}
