package io.helixiam.authorization.flow.magiclink;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Helix IAM: default in-process {@link MagicLinkTokenStore} (single-instance / dev). A Redis-backed
 * store replaces it for horizontal scale (@ConditionalOnMissingBean in FlowConfig). Tokens are
 * short-lived and single-use, so growth is bounded.
 */
public class InMemoryMagicLinkTokenStore implements MagicLinkTokenStore {

    private final ConcurrentMap<String, MagicLinkToken> tokens = new ConcurrentHashMap<>();

    @Override
    public void save(final MagicLinkToken token) {
        tokens.put(token.token(), token);
    }

    @Override
    public Optional<MagicLinkToken> find(final String token) {
        return Optional.ofNullable(tokens.get(token));
    }

    @Override
    public void remove(final String token) {
        tokens.remove(token);
    }
}
