package group.mfnr.authorization.flow.magiclink;

import java.util.Optional;

/**
 * Helix IAM: store for passwordless magic-link tokens, keyed by token. Shared across publisher
 * instances (issued on one node, clicked on another), so a Redis-backed impl drops in for scale;
 * in-process {@link InMemoryMagicLinkTokenStore} is the default.
 */
public interface MagicLinkTokenStore {

    void save(MagicLinkToken token);

    Optional<MagicLinkToken> find(String token);

    void remove(String token);
}
