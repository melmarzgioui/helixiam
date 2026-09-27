/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import io.helixiam.authorization.security.session.AuthTimeStamper;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

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
 *   <li><b>Browser sessions</b> (rc.6 item 7b) — every browser the user is signed in with in this realm, whether
 *       or not it signed in to an application: the {@link BrowserSessionRegistry} rows checked against the
 *       HTTP-session store (Redis or queue), joined with the SSO sessions by {@code sid}. Each can be signed out on
 *       its own.</li>
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
    private final BrowserSessionRegistry browserSessions;
    private final ObjectProvider<SessionRepository<?>> httpSessionStore;
    private final HttpSessionTerminator httpSessions;
    private final SessionRevocation revocation;
    private final String idpBaseUrl;

    public AccountSessionService(final SessionAdminService sessionAdminService,
                                 final SsoSessionStore ssoSessionStore,
                                 final SsoLogoutService ssoLogoutService,
                                 final BrowserSessionRegistry browserSessions,
                                 final ObjectProvider<SessionRepository<?>> httpSessionStore,
                                 final HttpSessionTerminator httpSessions,
                                 final SessionRevocation revocation,
                                 @Value("${idp.base.url}") final String idpBaseUrl) {
        this.sessionAdminService = sessionAdminService;
        this.ssoSessionStore = ssoSessionStore;
        this.ssoLogoutService = ssoLogoutService;
        this.browserSessions = browserSessions;
        this.httpSessionStore = httpSessionStore;
        this.httpSessions = httpSessions;
        this.revocation = revocation;
        this.idpBaseUrl = idpBaseUrl;
    }

    /**
     * One place the user is signed in, for the account console.
     *
     * @param sid      the sign-in's OIDC {@code sid} (the handle to sign it out; not a credential)
     * @param current  this browser
     * @param device   browser and system it signed in from ({@link DeviceLabel#UNKNOWN} when not known)
     * @param signedIn when it signed in, or null
     * @param lastUsed when it was last used (its last request, or its apps' last token), or null
     * @param apps     the applications it signed in to (client ids)
     */
    public record BrowserSession(String sid, boolean current, DeviceLabel device, Instant signedIn, Instant lastUsed,
                                 List<String> apps) {
    }

    /**
     * rc.6 item 7b: every browser the user is signed in with in this realm, this one first, then the most recently
     * used. A browser that signed in only to the account console is listed too; a sign-in whose browser session has
     * ended but whose apps still hold tokens is listed with its apps.
     *
     * @param currentSid           this browser's {@code sid} (null before its sign-in completed)
     * @param currentDevice        this browser's device (from this request)
     * @param currentAuthTimeMillis this browser's sign-in time, or null
     */
    public List<BrowserSession> listBrowserSessions(final String realmId, final String userId, final String currentSid,
                                                    final DeviceLabel currentDevice, final Long currentAuthTimeMillis) {
        final Map<String, SsoSessionView> ssoBySid = new LinkedHashMap<>();
        for (final SsoSessionView s : listSessions(realmId, userId)) {
            ssoBySid.put(s.ssoSessionId(), s);
        }
        final SessionRevocation.State state = revocation.state(userId);
        final List<BrowserSession> out = new ArrayList<>();
        final Set<String> listed = new HashSet<>();
        final Map<String, BrowserSessionRegistry.Entry> gone = new LinkedHashMap<>();
        for (final BrowserSessionRegistry.Entry entry : browserSessions.forUser(userId)) {
            final SsoSessionView sso = ssoBySid.get(entry.sid());
            if (entry.sid().equals(currentSid)) {
                out.add(new BrowserSession(entry.sid(), true, entry.device(), entry.signedInAt(), Instant.now(),
                        apps(sso)));
                listed.add(entry.sid());
                continue;
            }
            final Optional<Session> live = liveSession(entry, userId, state);
            if (live.isPresent()) {
                final Instant lastUsed = latest(live.get().getLastAccessedTime(), sso == null ? null : sso.issuedAt());
                out.add(new BrowserSession(entry.sid(), false, entry.device(), entry.signedInAt(), lastUsed,
                        apps(sso)));
                listed.add(entry.sid());
            } else {
                gone.put(entry.sid(), entry);
            }
        }
        for (final SsoSessionView sso : ssoBySid.values()) {
            if (listed.contains(sso.ssoSessionId())) {
                continue;
            }
            final boolean current = sso.ssoSessionId().equals(currentSid);
            // A row without any issued token is an authorization code nobody redeemed (an abandoned or blocked
            // sign-in), not a place the user is signed in; "sign out everywhere else" still revokes it.
            if (!current && sso.issuedAt() == null) {
                continue;
            }
            final BrowserSessionRegistry.Entry entry = gone.remove(sso.ssoSessionId());
            final Instant firstToken = sso.clients().stream().map(SsoSessionView.ClientView::issuedAt)
                    .filter(java.util.Objects::nonNull).min(Comparator.naturalOrder()).orElse(sso.issuedAt());
            out.add(new BrowserSession(sso.ssoSessionId(), current,
                    entry != null ? entry.device() : current ? currentDevice : DeviceLabel.UNKNOWN,
                    entry != null ? entry.signedInAt() : firstToken, current ? Instant.now() : sso.issuedAt(),
                    apps(sso)));
            listed.add(sso.ssoSessionId());
        }
        // Rows whose browser session and apps are both gone: forget them.
        gone.keySet().forEach(sid -> browserSessions.remove(userId, sid));
        if (currentSid == null || !listed.contains(currentSid)) {
            out.add(new BrowserSession(currentSid, true, currentDevice,
                    currentAuthTimeMillis == null ? null : Instant.ofEpochMilli(currentAuthTimeMillis), Instant.now(),
                    List.of()));
        }
        out.sort(Comparator.comparing((BrowserSession b) -> !b.current())
                .thenComparing(BrowserSession::lastUsed, Comparator.nullsLast(Comparator.reverseOrder())));
        return out;
    }

    /**
     * rc.6 item 7b: signs out one of the user's other browsers: its apps' tokens are revoked and they get a
     * back-channel logout, and its browser session ends. {@code false} (nothing done) for this browser, an unknown
     * sign-in or one that is not the user's.
     */
    public boolean signOutBrowser(final String realmId, final String userId, final String sid,
                                  final String currentSid) {
        if (sid == null || sid.isBlank() || sid.equals(currentSid) || userId == null) {
            return false;
        }
        final Optional<BrowserSessionRegistry.Entry> entry = browserSessions.find(userId, sid);
        final boolean ssoOwned = ownsSession(userId, sid);
        if (entry.isEmpty() && !ssoOwned) {
            LOG.warn("Refusing to sign out browser session {}: not a session of the user", LogSafe.sanitize(sid));
            return false;
        }
        if (ssoOwned) {
            ssoLogoutService.terminate(sid, realmId, idpBaseUrl + "/realms/" + realmId);
        }
        entry.ifPresent(e -> {
            httpSessions.deleteAll(List.of(e.httpSessionId()));
            browserSessions.remove(userId, sid);
        });
        LOG.info("User {} signed out one of their browser sessions in realm {}", LogSafe.sanitize(userId),
                LogSafe.sanitize(realmId));
        return true;
    }

    /**
     * The HTTP session of {@code entry} if it still exists, still carries this sign-in of this user, and was not ended
     * by "sign out everywhere else" ({@link SessionRevocation}, which ends it only on its next request).
     */
    private Optional<Session> liveSession(final BrowserSessionRegistry.Entry entry, final String userId,
                                          final SessionRevocation.State state) {
        final SessionRepository<?> repository = httpSessionStore.getIfAvailable();
        if (repository == null) {
            return Optional.empty();
        }
        final Session session;
        try {
            session = repository.findById(entry.httpSessionId());
        } catch (final RuntimeException e) {
            LOG.debug("Could not read a browser session of user {}: {}", LogSafe.sanitize(userId),
                    LogSafe.sanitize(e.getClass().getName()));
            return Optional.empty();
        }
        if (session == null || session.isExpired()
                || !entry.sid().equals(session.getAttribute(AuthTimeStamper.HELIX_SID))) {
            return Optional.empty();
        }
        final Object authMs = session.getAttribute(AuthTimeStamper.HELIX_AUTH_TIME_MS);
        final Object authSecs = session.getAttribute(AuthTimeStamper.HELIX_AUTH_TIME);
        final Long authTime = authMs instanceof Long ms ? ms : authSecs instanceof Long secs ? secs * 1000L : null;
        final Long kept = session.getAttribute(SessionRevocation.KEPT_ATTRIBUTE) instanceof Long k ? k : null;
        return SessionRevocation.valid(state, authTime, session.getCreationTime().toEpochMilli(), kept)
                ? Optional.of(session) : Optional.empty();
    }

    private static List<String> apps(final SsoSessionView sso) {
        return sso == null ? List.of()
                : sso.clients().stream().map(SsoSessionView.ClientView::clientId).distinct().toList();
    }

    private static Instant latest(final Instant a, final Instant b) {
        return a == null ? b : b == null ? a : a.isAfter(b) ? a : b;
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
            LOG.warn("Refusing self session revoke {} — not owned by principal", LogSafe.sanitize(ssoSessionId));
            return false;
        }
        ssoLogoutService.terminate(ssoSessionId, realmId, idpBaseUrl + "/realms/" + realmId);
        LOG.info("User {} revoked their own SSO session {} in realm {}",
                LogSafe.sanitize(principalName), LogSafe.sanitize(ssoSessionId), LogSafe.sanitize(realmId));
        return true;
    }

    /**
     * B1 "sign out everywhere else": ends every SSO session of the caller in this realm except {@code keepSid} (this
     * browser's), with back-channel logout to their applications, and leaves the HTTP sessions to
     * {@link SessionRevocation}. Returns how many sessions were ended.
     */
    public int signOutOthers(final String realmId, final String principalName, final String keepSid) {
        int ended = 0;
        for (final SsoSessionView session : listSessions(realmId, principalName)) {
            if (keepSid != null && keepSid.equals(session.ssoSessionId())) {
                continue;
            }
            if (ssoLogoutService.terminate(session.ssoSessionId(), realmId, idpBaseUrl + "/realms/" + realmId, false) != null) {
                ended++;
            }
        }
        // rc.6 item 7b: end the other browsers' sessions now (SessionRevocation would end them on their next request).
        for (final BrowserSessionRegistry.Entry entry : browserSessions.forUser(principalName)) {
            if (!entry.sid().equals(keepSid)) {
                httpSessions.deleteAll(List.of(entry.httpSessionId()));
                browserSessions.remove(principalName, entry.sid());
            }
        }
        LOG.info("User {} signed out {} other session(s) in realm {}",
                LogSafe.sanitize(principalName), ended, LogSafe.sanitize(realmId));
        return ended;
    }

    /** B1 account deletion: ends every SSO session of the caller in this realm, with back-channel logout. */
    public int signOutAll(final String realmId, final String principalName) {
        int ended = 0;
        for (final SsoSessionView session : listSessions(realmId, principalName)) {
            if (ssoLogoutService.terminate(session.ssoSessionId(), realmId, idpBaseUrl + "/realms/" + realmId) != null) {
                ended++;
            }
        }
        return ended;
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
            LOG.info("User {} revoked consent for application {} in realm {}",
                    LogSafe.sanitize(principalName), LogSafe.sanitize(clientId), LogSafe.sanitize(realmId));
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
