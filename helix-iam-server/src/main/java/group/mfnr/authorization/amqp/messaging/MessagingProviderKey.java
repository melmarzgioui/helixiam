package group.mfnr.authorization.amqp.messaging;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Helix IAM notifications (N2): identifies one provider for delete — realm + channel + driver. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MessagingProviderKey(String realmId, String channel, String driver) {
}
