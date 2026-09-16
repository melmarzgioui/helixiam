package io.helixiam.authorization.flow.magiclink;

import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * Helix IAM: passwordless magic-link login (deferred from E3.4, grouped with Epic 4's out-of-band
 * mechanisms). {@link #request} mints a single-use, TTL-bound token for a user and emails the
 * clickable link via the {@link MagicLinkSender}; {@link #verify} consumes the token exactly once
 * and returns the bound user. Wiring the verified user into an authenticated session is left to the
 * publisher's AMQP-based auth path (a follow-up); this is the reusable, fully-tested core.
 */
public class MagicLinkService {

    private final MagicLinkTokenStore store;
    private final MagicLinkSender sender;
    private final Supplier<String> tokenGenerator;
    private final LongSupplier clock;
    private final long ttlMillis;
    private final String linkBaseUrl;

    public MagicLinkService(final MagicLinkTokenStore store, final MagicLinkSender sender,
                            final Supplier<String> tokenGenerator, final LongSupplier clock,
                            final long ttlMillis, final String linkBaseUrl) {
        this.store = store;
        this.sender = sender;
        this.tokenGenerator = tokenGenerator;
        this.clock = clock;
        this.ttlMillis = ttlMillis;
        this.linkBaseUrl = linkBaseUrl;
    }

    /** Mints a single-use token for the user and emails the magic link. */
    public void request(final String userId, final String email) {
        final String token = tokenGenerator.get();
        store.save(new MagicLinkToken(token, userId, clock.getAsLong(), ttlMillis));
        sender.send(new MagicLinkMessage(userId, email, linkBaseUrl + "?token=" + token));
    }

    /** Consumes the token exactly once; returns the bound user id, or null if invalid/expired/used. */
    public String verify(final String token) {
        final MagicLinkToken stored = store.find(token).orElse(null);
        if (stored == null) {
            return null;
        }
        final String userId = stored.consume(clock.getAsLong());
        if (userId != null) {
            store.save(stored);
        }
        return userId;
    }
}
