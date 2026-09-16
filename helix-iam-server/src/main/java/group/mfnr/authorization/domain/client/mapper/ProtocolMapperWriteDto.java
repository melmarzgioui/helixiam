package group.mfnr.authorization.domain.client.mapper;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM (Wave 3): create/update payload for a per-client protocol mapper (subscriber copy). {@code mapperId}
 * is null on create. {@code realmId}/{@code clientId} scope the mapper to its client.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ProtocolMapperWriteDto(String mapperId, String realmId, String clientId, String name, String mapperType,
                                     String source, String claimName, Boolean addToAccessToken, Boolean addToIdToken) {
}
