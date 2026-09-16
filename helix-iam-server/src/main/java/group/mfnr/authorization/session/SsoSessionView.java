package group.mfnr.authorization.session;

import java.time.Instant;
import java.util.List;

/**
 * Helix IAM SSO P7: the admin/console view of one SSO session — a single browser login rolled up across
 * every client it touched. Unlike the internal {@link SsoSession}, each client here is labelled with its
 * human OAuth {@code clientId} (not the internal registered-client id).
 */
public record SsoSessionView(String ssoSessionId, String principalName, String realm,
                             Instant issuedAt, Instant expiresAt, List<ClientView> clients) {

    /** One client within the SSO session, as shown in the console. */
    public record ClientView(String clientId, String grantType, List<String> scopes,
                             Instant issuedAt, Instant expiresAt) {
    }
}
