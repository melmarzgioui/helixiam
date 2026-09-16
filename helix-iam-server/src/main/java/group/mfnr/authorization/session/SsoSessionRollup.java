package group.mfnr.authorization.session;

import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM SSO P4: pure grouping of OAuth2 authorizations into {@link SsoSession}s by their {@code sid}.
 * Authorizations with no {@code sid} (service accounts / client_credentials) have no SSO session and are
 * dropped. Session start = earliest authorization issuance; session end = latest token expiry.
 */
public final class SsoSessionRollup {

    /** One OAuth2 authorization row, tagged with the {@code sid} (or principal) it groups under. */
    public record Entry(String sid, String authorizationId, String clientId, String principalName, String grantType,
                        List<String> scopes, Instant issuedAt, Instant expiresAt) {
    }

    private SsoSessionRollup() {
    }

    /**
     * Convert a deserialized {@link OAuth2Authorization} into a rollup {@link Entry} (or {@code null} for a
     * service-account / {@code client_credentials} authorization, which is not an interactive SSO session).
     * Shared by the Redis and queue SSO readers. Groups by the OIDC {@code sid} when present, else principal.
     */
    public static Entry entryOf(final OAuth2Authorization a) {
        final String grantType = a.getAuthorizationGrantType().getValue();
        if ("client_credentials".equals(grantType)) {
            return null;
        }
        final String principal = a.getPrincipalName();
        final String sid = sidOf(a);
        final String sessionKey = sid != null ? sid : principal;
        return new Entry(sessionKey, a.getId(), a.getRegisteredClientId(), principal, grantType,
                new ArrayList<>(a.getAuthorizedScopes()), issuedAt(a), expiresAt(a));
    }

    private static String sidOf(final OAuth2Authorization a) {
        final OAuth2Authorization.Token<OidcIdToken> idToken = a.getToken(OidcIdToken.class);
        if (idToken == null || idToken.getToken().getClaims() == null) {
            return null;
        }
        final Object sid = idToken.getToken().getClaims().get("sid");
        return sid == null ? null : sid.toString();
    }

    private static Instant issuedAt(final OAuth2Authorization a) {
        return a.getAccessToken() != null ? a.getAccessToken().getToken().getIssuedAt() : null;
    }

    private static Instant expiresAt(final OAuth2Authorization a) {
        if (a.getRefreshToken() != null && a.getRefreshToken().getToken().getExpiresAt() != null) {
            return a.getRefreshToken().getToken().getExpiresAt();
        }
        return a.getAccessToken() != null ? a.getAccessToken().getToken().getExpiresAt() : null;
    }

    public static List<SsoSession> assemble(final List<Entry> entries) {
        return assemble(entries, Instant.now());
    }

    /**
     * Roll authorizations up into SSO sessions as of {@code now}. Fully-expired authorizations (their tokens
     * have all lapsed) are dropped — otherwise stale logins linger in the store and inflate a session's
     * "signed in" time and app list. Within a session the same app is shown once (the most recent
     * authorization for that client id). A session whose authorizations have all expired disappears.
     */
    public static List<SsoSession> assemble(final List<Entry> entries, final Instant now) {
        final Map<String, List<Entry>> bySid = new LinkedHashMap<>();
        for (final Entry e : entries) {
            if (e == null || e.sid() == null || e.sid().isBlank()) {
                continue; // no session → not an SSO session
            }
            if (e.expiresAt() != null && e.expiresAt().isBefore(now)) {
                continue; // expired authorization → not a live session
            }
            bySid.computeIfAbsent(e.sid(), k -> new ArrayList<>()).add(e);
        }

        final List<SsoSession> sessions = new ArrayList<>();
        bySid.forEach((sid, group) -> {
            // One row per app (client id): keep the most recent authorization for each client.
            final Map<String, SsoSession.ClientInSession> byClient = new LinkedHashMap<>();
            for (final Entry e : group) {
                final SsoSession.ClientInSession existing = byClient.get(e.clientId());
                final boolean newer = existing == null || existing.issuedAt() == null
                        || (e.issuedAt() != null && e.issuedAt().isAfter(existing.issuedAt()));
                if (newer) {
                    byClient.put(e.clientId(), new SsoSession.ClientInSession(
                            e.authorizationId(), e.clientId(), e.grantType(), e.scopes(), e.issuedAt(), e.expiresAt()));
                }
            }
            final List<SsoSession.ClientInSession> clients = new ArrayList<>(byClient.values());
            final String principal = group.stream().map(Entry::principalName).filter(p -> p != null).findFirst().orElse(null);
            // "Signed in" = most recent authentication in this session (the session may span repeat logins
            // when the id_token carries no sid and authorizations group by principal); end = latest expiry.
            final Instant issued = group.stream().map(Entry::issuedAt).filter(i -> i != null).max(Comparator.naturalOrder()).orElse(null);
            final Instant expires = group.stream().map(Entry::expiresAt).filter(i -> i != null).max(Comparator.naturalOrder()).orElse(null);
            sessions.add(new SsoSession(sid, principal, clients, issued, expires));
        });
        return sessions;
    }
}
