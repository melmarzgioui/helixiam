/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.magiclink;

import org.junit.jupiter.api.Test;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM (deferred from E3.4, grouped into Epic 4's out-of-band mechanisms): passwordless
 * magic-link login. A single-use, TTL-bound token is emailed as a link; clicking it verifies the
 * token exactly once and yields the bound user. These tests pin issuance, the emailed link, and the
 * single-use/expiry security of verification. (Wiring the verified user into a session is integration
 * left for the publisher's AMQP-based auth path; this is the reusable, fully-tested core.)
 */
class MagicLinkServiceTest {

    private static final long TTL = 600_000L; // 10 minutes

    private final InMemoryMagicLinkTokenStore store = new InMemoryMagicLinkTokenStore();
    private final Deque<String> tokens = new ArrayDeque<>();
    private final AtomicReference<MagicLinkMessage> sent = new AtomicReference<>();
    private final MagicLinkSender sender = sent::set;

    private MagicLinkService service() {
        return new MagicLinkService(store, sender, tokens::removeFirst, () -> 0L, TTL,
                "https://idp.kubedna.io/login/magic");
    }

    @Test
    void request_mintsATokenAndEmailsTheLink() {
        tokens.add("tok-1");
        service().request("user-7", "user@example.com");

        assertThat(store.find("tok-1")).isPresent();
        assertThat(sent.get().userId()).isEqualTo("user-7");
        assertThat(sent.get().email()).isEqualTo("user@example.com");
        assertThat(sent.get().link()).isEqualTo("https://idp.kubedna.io/login/magic?token=tok-1");
    }

    @Test
    void verify_returnsTheUserForAValidTokenExactlyOnce() {
        tokens.add("tok-1");
        final MagicLinkService service = service();
        service.request("user-7", "user@example.com");

        assertThat(service.verify("tok-1")).isEqualTo("user-7");
        assertThat(service.verify("tok-1")).isNull(); // single-use
    }

    @Test
    void verify_rejectsAnUnknownToken() {
        assertThat(service().verify("ghost")).isNull();
    }

    @Test
    void verify_rejectsAnExpiredToken() {
        tokens.add("tok-1");
        final MagicLinkService service = new MagicLinkService(store, sender, tokens::removeFirst,
                () -> TTL, TTL, "https://idp.kubedna.io/login/magic"); // clock already at expiry
        // mint at t=TTL with createdAt=TTL; verify also at TTL -> expired (>= ttl since creation is 0 elapsed?)
        service.request("user-7", "user@example.com");
        assertThat(service.verify("tok-1")).isEqualTo("user-7"); // 0 elapsed, still valid

        final InMemoryMagicLinkTokenStore store2 = new InMemoryMagicLinkTokenStore();
        store2.save(new MagicLinkToken("old", "user-7", 0L, TTL));
        final MagicLinkService expiredService = new MagicLinkService(store2, sender,
                () -> "x", () -> TTL, TTL, "base");
        assertThat(expiredService.verify("old")).isNull(); // TTL elapsed -> expired
    }
}
