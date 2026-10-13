/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import io.helixiam.testsupport.RebindingTarget;
import io.helixiam.testsupport.TestTls;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * M6: the admin-triggered document fetch ({@link OutboundUrlGuard#fetch}, SAML metadata import) connects to the
 * address the guard validated on every hop, never a second DNS answer, and keeps its messages.
 */
class OutboundUrlGuardFetchRebindingTest {

    @Test
    void theDocumentIsFetchedFromTheValidatedAddressOnly() {
        final TestTls tls = TestTls.createFor("metadata-rebind", "md.rebind.test");
        try (RebindingTarget target = RebindingTarget.https("md.rebind.test", tls)) {
            target.respond(s -> new RebindingTarget.Answer(200, "application/samlmetadata+xml", "<EntityDescriptor/>"));
            final OutboundUrlGuard guard = withTrust(target.guard(), tls);

            final String xml = guard.fetch(target.url("https", "/metadata"), "application/samlmetadata+xml", true);

            assertThat(xml).isEqualTo("<EntityDescriptor/>");
            assertThat(target.requests()).hasSize(1);
            assertThat(target.requests().get(0).header("Accept")).isEqualTo("application/samlmetadata+xml");
            assertThat(target.lookups()).isEqualTo(1);
        }
    }

    @Test
    void aRedirectHopResolvesAgainAndARebindingAnswerIsRefused() {
        final TestTls tls = TestTls.createFor("metadata-rebind", "md.rebind.test");
        try (RebindingTarget target = RebindingTarget.https("md.rebind.test", tls)) {
            target.respond(s -> s.path().equals("/old")
                    ? new RebindingTarget.Answer(302, null, null, java.util.Map.of("Location", "/new"))
                    : new RebindingTarget.Answer(200, "text/xml", "<x/>"));
            final OutboundUrlGuard guard = withTrust(target.guard(), tls);

            assertThatThrownBy(() -> guard.fetch(target.url("https", "/old"), "text/xml", true))
                    .isInstanceOf(SsrfBlockedException.class);
            // the first hop used the validated answer; the redirect hop resolved again, got the metadata address and was
            // refused before connecting
            assertThat(target.requests()).extracting(RebindingTarget.Seen::path).containsExactly("/old");
            assertThat(target.lookups()).isEqualTo(2);
        }
    }

    /** The scenario's guard, trusting the test CA for the fetch's TLS. */
    private static OutboundUrlGuard withTrust(final OutboundUrlGuard guard, final TestTls tls) {
        guard.setFetchTls(io.helixiam.authorization.messaging.email.TlsTrust.context(tls.caPem()));
        return guard;
    }

    @Test
    void keepsItsMessagesForRefusedTargets() {
        final OutboundUrlGuard blocking = new OutboundUrlGuard(false, List.of(),
                host -> new InetAddress[] {InetAddress.getByAddress(host, new byte[] {10, 0, 0, 1})});
        assertThatThrownBy(() -> blocking.fetch("https://internal.example/md", "text/xml", true))
                .isInstanceOf(SsrfBlockedException.class).hasMessageNotContaining("Connection");
    }

    @Test
    void aRedirectWithALargeBodyIsStillFollowed() {
        final TestTls tls = TestTls.createFor("metadata-rebind", "md.rebind.test");
        try (RebindingTarget target = RebindingTarget.https("md.rebind.test", tls)) {
            target.respond(s -> s.path().equals("/old")
                    ? new RebindingTarget.Answer(302, "text/html", "x".repeat(2 * 1024 * 1024),
                            java.util.Map.of("Location", "/new"))
                    : new RebindingTarget.Answer(200, "text/xml", "<x/>"));
            final OutboundUrlGuard guard = withTrust(target.guard(2), tls);
            assertThat(guard.fetch(target.url("https", "/old"), "text/xml", true)).isEqualTo("<x/>");
        }
    }
}
