package io.helixiam.authorization.session;

import java.util.List;

/**
 * Helix IAM E8.5-S4: read seam over the OAuth2 authorization store for the Sessions admin screen.
 * Listing is not part of Spring's {@code OAuth2AuthorizationService}, so it lives here; revocation
 * still goes through the authorization service so it works for any backing store.
 */
public interface SessionStore {

    /** Every currently-stored authorization (active session), newest-issued not guaranteed. */
    List<SessionRow> findAll();
}
