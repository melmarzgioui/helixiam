package group.mfnr.authorization.federation.saml;

import java.time.Instant;

/**
 * Helix IAM E5.2 follow-up: one-time-use guard for SAML assertions. Records an assertion ID until
 * its validity window ({@code NotOnOrAfter}) passes and rejects any repeat within that window —
 * closing the assertion-replay vector that signature + condition checks alone do not.
 *
 * <p>Default impl is in-process ({@link InMemorySamlAssertionReplayCache}); a Redis-backed cache
 * replaces it for horizontal scale via {@code @ConditionalOnMissingBean}, like the other Helix stores.
 */
public interface SamlAssertionReplayCache {

    /**
     * Record the assertion ID if not already seen within its window.
     *
     * @return {@code true} if this is the first sighting (accepted); {@code false} if it is a replay.
     */
    boolean checkAndRecord(String assertionId, Instant expiresAt);
}
