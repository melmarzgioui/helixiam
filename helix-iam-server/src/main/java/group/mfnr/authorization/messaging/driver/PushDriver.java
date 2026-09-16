package group.mfnr.authorization.messaging.driver;

import group.mfnr.authorization.amqp.messaging.ResolvedProviderDto;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM notifications (N6c): delivers one push notification to a user's device tokens via a specific
 * platform ({@code FCM} / {@code APNS}). The registry selects the driver whose {@link #driver()} matches the
 * resolved provider's driver id. {@code data} carries the structured payload the app acts on (e.g. the push
 * approval id, challenge and number-matching choices).
 */
public interface PushDriver {

    /** The provider {@code driver} id this handles ({@code FCM} / {@code APNS}). */
    String driver();

    /** Push {@code title}/{@code body} (+ structured {@code data}) to each token; throws on a hard failure. */
    void send(ResolvedProviderDto provider, List<String> tokens, String title, String body, Map<String, String> data);
}
