package group.mfnr.authorization.session;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM (6) Self-service Account: the END-USER view of their own SSO sessions and granted application
 * consents, derived from the same SSO-session model the admin Sessions screen uses ({@link SessionAdminService})
 * but always filtered to the caller's {@code principalName}. A user can only ever see and revoke
 * <em>their own</em> sessions/consents — every method takes the authenticated principal's id and discards
 * sessions that do not belong to it.
 *
 * <ul>
 *   <li><b>Sessions</b> — one row per browser login (this realm's clients rolled up); revoke cascades a
 *       Single Logout, but only for a session that belongs to the caller.</li>
 *   <li><b>Consents</b> — the distinct applications the caller has authorized across their sessions; revoking
 *       a consent terminates every of the caller's sessions that touched that application.</li>
 * </ul>
 */
@Service
public class AccountSessionService {

    private static final Logger LOG = LogManager.getLogger(AccountSessionService.class);

    private final SessionAdminService sessionAdminService;
    private final SsoSessionStore ssoSessionStore;
    private final SsoLogoutService ssoLogoutService;
    private final String idpBaseUrl;

    public AccountSessionService(final SessionAdminService sessionAdminService,
                                 final SsoSessionStore ssoSessionStore,
                                 final SsoLogoutService ssoLogoutService,
                                 @Value("${idp.base.url}") final String idpBaseUrl) {
        this.sessionAdminService = sessionAdminService;
        this.ssoSessionStore = ssoSessionStore;
        this.ssoLogoutService = ssoLogoutService;
        this.idpBaseUrl = idpBaseUrl;
    }

    /** The caller's own SSO sessions in this realm, newest first. */
    public List<SsoSessionView> listSessions(final String realmId, final String principalName) {
        return sessionAdminService.listSso(realmId).stream()
                .filter(s -> principalName != null && principalName.equals(s.principalName()))
                .toList();
    }

    /** Revoke (Single Logout) one of the caller's own sessions; {@code false} if it is not theirs. */
    public boolean revokeSession(final String realmId, final String principalName, final String ssoSessionId) {
        if (!ownsSession(principalName, ssoSessionId)) {
            LOG.warn("Refusing self session revoke {} — not owned by principal", ssoSessionId);
            return false;
        }
        ssoLogoutService.terminate(ssoSessionId, realmId, idpBaseUrl + "/realms/" + realmId);
        LOG.info("User {} revoked their own SSO session {} in realm {}", principalName, ssoSessionId, realmId);
        return true;
    }

    /** The distinct applications the caller has authorized across their own sessions (their consents). */
    public List<AccountConsent> listConsents(final String realmId, final String principalName) {
        final Map<String, AccountConsent> byClient = new LinkedHashMap<>();
        for (final SsoSessionView session : listSessions(realmId, principalName)) {
            for (final SsoSessionView.ClientView client : session.clients()) {
                byClient.merge(client.clientId(),
                        new AccountConsent(client.clientId(), new ArrayList<>(client.scopes()), client.issuedAt()),
                        AccountConsent::mergedWith);
            }
        }
        return byClient.values().stream()
                .sorted(Comparator.comparing(AccountConsent::clientId))
                .toList();
    }

    /**
     * Revoke the caller's consent for an application — terminates every of the caller's own sessions that
     * touched that client. {@code false} when the caller has no session for that client.
     */
    public boolean revokeConsent(final String realmId, final String principalName, final String clientId) {
        final List<SsoSessionView> mySessions = listSessions(realmId, principalName);
        boolean revokedAny = false;
        for (final SsoSessionView session : mySessions) {
            final boolean touchesClient = session.clients().stream().anyMatch(c -> c.clientId().equals(clientId));
            if (touchesClient) {
                ssoLogoutService.terminate(session.ssoSessionId(), realmId, idpBaseUrl + "/realms/" + realmId);
                revokedAny = true;
            }
        }
        if (revokedAny) {
            LOG.info("User {} revoked consent for application {} in realm {}", principalName, clientId, realmId);
        }
        return revokedAny;
    }

    /** Defence in depth: confirm the SSO session actually belongs to this principal before touching it. */
    private boolean ownsSession(final String principalName, final String ssoSessionId) {
        final SsoSession session = ssoSessionStore.findById(ssoSessionId);
        return session != null && principalName != null && principalName.equals(session.principalName());
    }

    /** One authorized application (consent) for the account-console Consents screen. */
    public record AccountConsent(String clientId, List<String> scopes, Instant grantedAt) {

        /** Union two consent rows for the same client (scopes merged, earliest grant kept). */
        AccountConsent mergedWith(final AccountConsent other) {
            final List<String> scopes = new ArrayList<>(this.scopes);
            for (final String s : other.scopes) {
                if (!scopes.contains(s)) {
                    scopes.add(s);
                }
            }
            final Instant granted = this.grantedAt == null ? other.grantedAt
                    : other.grantedAt == null ? this.grantedAt
                    : this.grantedAt.isBefore(other.grantedAt) ? this.grantedAt : other.grantedAt;
            return new AccountConsent(this.clientId, scopes, granted);
        }
    }
}
