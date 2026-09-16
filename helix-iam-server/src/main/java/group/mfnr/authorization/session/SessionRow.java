package group.mfnr.authorization.session;

import java.time.Instant;
import java.util.List;

/**
 * Helix IAM E8.5-S4: a raw row from the OAuth2 authorization store — the storage-shaped view of an
 * active session, before realm scoping and client labelling are applied.
 */
public record SessionRow(String id, String registeredClientId, String principalName, String grantType,
                         List<String> scopes, Instant issuedAt, Instant expiresAt) {
}
