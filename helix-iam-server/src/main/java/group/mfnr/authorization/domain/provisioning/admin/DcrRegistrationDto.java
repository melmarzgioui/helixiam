package group.mfnr.authorization.domain.provisioning.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM E11: a DCR registration binding (subscriber copy). Carries the management-credential hash so
 * the publisher can verify a RFC 7592 read/update/delete; {@code registrationToken} is populated only on
 * the create result (returned once).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DcrRegistrationDto(String registrationId, String realmId, String clientInternalId,
                                 String clientId, String registrationToken) {
}
