package group.mfnr.authorization.amqp.messaging;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/** Helix IAM notifications (N3): a resolved provider WITH secret for the sender path (publisher copy). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ResolvedProviderDto(String channel, String driver, String fromAddress, String fromName,
                                  Map<String, String> config, String secret) {
}
