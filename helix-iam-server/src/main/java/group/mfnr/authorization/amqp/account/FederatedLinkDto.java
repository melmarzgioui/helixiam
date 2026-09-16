package group.mfnr.authorization.amqp.account;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM B9: publisher-side copy of one of a user's federated-identity links (two-copy DTO; mirrors the
 * subscriber's {@code domain.federation.FederatedLinkView}). Shown on the account console's "Connected
 * accounts" screen.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FederatedLinkDto(String idpAlias, String externalSubject, Long linkedAt) {
}
