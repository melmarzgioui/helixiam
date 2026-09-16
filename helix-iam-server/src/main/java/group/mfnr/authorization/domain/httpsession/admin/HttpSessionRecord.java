package group.mfnr.authorization.domain.httpsession.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM (Q3): the wire form of a stored HTTP session (subscriber copy). The {@code blob} is opaque here. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record HttpSessionRecord(String sessionId, String principalName, String blob, Long creationTime,
                                Long lastAccessTime, Integer maxInactiveSeconds, Long expiryTime) {
}
