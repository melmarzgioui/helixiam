package group.mfnr.authorization.domain.agent;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Subscriber-side copy of the Agent (NHI) DTO carried over AMQP. Field ORDER must match the publisher copy
 * exactly (positional record over Jackson). Timestamps cross as epoch-millis {@code Long}s. {@link #from}
 * maps the entity.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AgentIdentityDto(String id, String realmId, String name, String displayName, String description,
                               String owner, String status, String authMethod, String clientId, String scopes,
                               boolean enabled, Long createdAt, Long expiresAt, Long lastUsedAt, String roles) {

    public static AgentIdentityDto from(final AgentIdentity a) {
        return new AgentIdentityDto(a.getId(), a.getRealmId(), a.getName(), a.getDisplayName(), a.getDescription(),
                a.getOwner(), a.getStatus(), a.getAuthMethod(), a.getClientId(), a.getScopes(), a.isEnabled(),
                a.getCreatedAt() == null ? null : a.getCreatedAt().getTime(),
                a.getExpiresAt() == null ? null : a.getExpiresAt().getTime(),
                a.getLastUsedAt() == null ? null : a.getLastUsedAt().getTime(), a.getRoles());
    }
}
