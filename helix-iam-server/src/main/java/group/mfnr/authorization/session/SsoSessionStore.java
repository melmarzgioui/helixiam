package group.mfnr.authorization.session;

import java.util.List;

/** Helix IAM SSO P4: reads the active SSO sessions (client authorizations rolled up by {@code sid}). */
public interface SsoSessionStore {

    /** Every active SSO session across all realms (caller filters by realm). */
    List<SsoSession> findAll();

    /** The SSO session with this {@code sid}, or {@code null} if none. */
    SsoSession findById(String ssoSessionId);
}
