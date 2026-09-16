package group.mfnr.authorization.amqp.messaging;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;

import java.util.Map;

/** Helix IAM notifications (N2): create/update payload for a messaging provider (secret write-only). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MessagingProviderWriteDto(String realmId,
                                        @NotBlank(message = "Channel is required.") String channel,
                                        @NotBlank(message = "Driver is required.") String driver, boolean enabled,
                                        String fromAddress, String fromName, Map<String, String> config,
                                        String secret) {
}
