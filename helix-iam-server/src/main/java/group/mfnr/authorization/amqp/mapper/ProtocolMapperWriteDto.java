package group.mfnr.authorization.amqp.mapper;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM (Wave 3): create/update payload for a per-client protocol mapper (publisher copy). {@code mapperId}
 * is null on create.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ProtocolMapperWriteDto(String mapperId, String realmId, String clientId, String name, String mapperType,
                                     String source, String claimName, Boolean addToAccessToken, Boolean addToIdToken) {
}
