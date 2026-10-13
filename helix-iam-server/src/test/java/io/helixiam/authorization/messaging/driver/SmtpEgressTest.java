/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.email.DeliveryResult;
import io.helixiam.authorization.messaging.email.DeliveryResult.Reason;
import io.helixiam.authorization.messaging.email.DeliveryResult.Status;
import io.helixiam.authorization.messaging.email.EmailAddress;
import io.helixiam.authorization.messaging.email.EmailMessage;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.testsupport.TestSmtpServer;
import io.helixiam.testsupport.TestTls;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SMTP is a realm-configured outbound connection: the host goes through the outbound guard (private, loopback and
 * metadata addresses refused unless the deployment allowlists the host), the connection goes to the address the guard
 * validated (TLS still verified against the configured name), only the SMTP ports are allowed unless the deployment
 * lists more, and a refusal names no internal detail.
 */
class SmtpEgressTest {

    private static ResolvedProviderDto provider(final String host, final int port, final Map<String, String> extra) {
        final Map<String, String> config = new LinkedHashMap<>();
        config.put("host", host);
        config.put("port", String.valueOf(port));
        config.put("connectTimeoutMs", "3000");
        config.put("readTimeoutMs", "5000");
        config.putAll(extra);
        return new ResolvedProviderDto("EMAIL", "SMTP", "no-reply@example.com", "Example", config, null);
    }

    private static EmailMessage message() {
        return new EmailMessage(EmailMessage.newMessageId(), null, List.of(EmailAddress.of("ada@example.org", "Ada")),
                null, "Hi", null, "Hello", Map.of());
    }

    /** host answers the server's address on the first lookup and the metadata address on every later one. */
    private static OutboundUrlGuard rebinding(final String host, final int port, final AtomicInteger lookups) {
        return new OutboundUrlGuard(false, List.of(host + ":" + port), name -> {
            final byte[] ip = lookups.getAndIncrement() == 0 ? new byte[] {127, 0, 0, 1}
                    : new byte[] {(byte) 169, (byte) 254, (byte) 169, (byte) 254};
            return new InetAddress[] {InetAddress.getByAddress(name, ip)};
        });
    }

    @Test
    void anInternalSmtpHostIsRefusedWithoutDetail() {
        final SmtpEmailDriver driver = new SmtpEmailDriver(DeploymentProfile.production(), OutboundUrlGuard.blocking(),
                Set.of());
        for (final String host : List.of("10.1.2.3", "127.0.0.1", "169.254.169.254", "[::1]")) {
            final DeliveryResult r = driver.deliver(provider(host, 587, Map.of()), message());
            assertThat(r.status()).as(host).isEqualTo(Status.PERMANENT_FAILURE);
            assertThat(r.reason()).isEqualTo(Reason.CONFIGURATION);
            assertThat(r.diagnostic()).doesNotContain(host.replace("[", "").replace("]", ""));
        }
    }

    @Test
    void onlyTheSmtpPortsAreAllowedUnlessTheDeploymentListsMore() {
        final OutboundUrlGuard publicDns = new OutboundUrlGuard(false, List.of(), name -> new InetAddress[] {
                InetAddress.getByAddress(name, new byte[] {93, (byte) 184, (byte) 216, 34})});
        final DeliveryResult r = new SmtpEmailDriver(DeploymentProfile.production(), publicDns, Set.of())
                .deliver(provider("smtp.example.com", 6379, Map.of()), message());
        assertThat(r.reason()).isEqualTo(Reason.CONFIGURATION);
        assertThat(r.diagnostic()).contains("port");
        assertThat(SmtpEmailDriver.ALLOWED_PORTS).containsExactlyInAnyOrder(25, 465, 587, 2525);
        assertThat(SmtpEmailDriver.parsePorts("2526, 10025")).containsExactlyInAnyOrder(2526, 10025);
        assertThat(SmtpEmailDriver.parsePorts("10025-10027")).containsExactlyInAnyOrder(10025, 10026, 10027);
    }

    @Test
    void theConnectionGoesToTheValidatedAddressOnly() throws Exception {
        try (TestSmtpServer server = TestSmtpServer.plain()) {
            final AtomicInteger lookups = new AtomicInteger();
            final SmtpEmailDriver driver = new SmtpEmailDriver(DeploymentProfile.development(),
                    rebinding("smtp.rebind.test", server.port(), lookups), Set.of(server.port()));

            final DeliveryResult r = driver.deliver(provider("smtp.rebind.test", server.port(),
                    Map.of("tlsMode", "NONE")), message());

            assertThat(r.status()).as(String.valueOf(r)).isEqualTo(Status.ACCEPTED);
            assertThat(server.await(x -> true, Duration.ofSeconds(5)).rcptTo()).containsExactly("<ada@example.org>");
            assertThat(lookups).hasValue(1);
        }
    }

    @Test
    void startTlsIsVerifiedAgainstTheConfiguredNameWhileConnectingToTheValidatedAddress() throws Exception {
        final TestTls tls = TestTls.createFor("smtp-rebind", "smtp.rebind.test");
        try (TestSmtpServer server = TestSmtpServer.startTls(tls)) {
            final AtomicInteger lookups = new AtomicInteger();
            final SmtpEmailDriver driver = new SmtpEmailDriver(DeploymentProfile.production(),
                    rebinding("smtp.rebind.test", server.port(), lookups), Set.of(server.port()));

            final DeliveryResult r = driver.deliver(provider("smtp.rebind.test", server.port(),
                    Map.of("tlsMode", "STARTTLS_REQUIRED", "caBundle", tls.caPem())), message());

            assertThat(r.status()).as(String.valueOf(r)).isEqualTo(Status.ACCEPTED);
            assertThat(server.await(x -> true, Duration.ofSeconds(5)).tls()).isTrue();
            assertThat(lookups).hasValue(1);

            // a certificate for another name is still refused
            final TestTls other = TestTls.createFor("smtp-other", "other.test");
            try (TestSmtpServer wrong = TestSmtpServer.startTls(other)) {
                final AtomicInteger l2 = new AtomicInteger();
                final DeliveryResult refused = new SmtpEmailDriver(DeploymentProfile.production(),
                        rebinding("smtp.rebind.test", wrong.port(), l2), Set.of(wrong.port()))
                        .deliver(provider("smtp.rebind.test", wrong.port(),
                                Map.of("tlsMode", "STARTTLS_REQUIRED", "caBundle", other.caPem())), message());
                assertThat(refused.status()).isNotEqualTo(Status.ACCEPTED);
            }
        }
    }

    /**
     * SMTPS (implicit TLS): Angus connects its own socket for an SSL socket factory, so the configured name must never
     * reach it. The name here does not resolve on the real network: any lookup outside the guard fails the send.
     */
    @Test
    void implicitTlsConnectsToTheValidatedAddressOnly() throws Exception {
        final String name = "smtps-pin-probe.invalid";
        final TestTls tls = TestTls.createFor("smtps-rebind", name);
        try (TestSmtpServer server = TestSmtpServer.implicitTls(tls)) {
            final AtomicInteger lookups = new AtomicInteger();
            final SmtpEmailDriver driver = new SmtpEmailDriver(DeploymentProfile.production(),
                    rebinding(name, server.port(), lookups), Set.of(server.port()));

            final DeliveryResult r = driver.deliver(provider(name, server.port(),
                    Map.of("tlsMode", "IMPLICIT", "caBundle", tls.caPem())), message());

            assertThat(r.status()).as(String.valueOf(r)).isEqualTo(Status.ACCEPTED);
            final TestSmtpServer.Received got = server.await(x -> true, Duration.ofSeconds(5));
            assertThat(got.tls()).isTrue();
            assertThat(got.rcptTo()).containsExactly("<ada@example.org>");
            assertThat(lookups).hasValue(1);
        }
    }

    @Test
    void implicitTlsRefusesACertificateForAnotherName() throws Exception {
        final TestTls other = TestTls.createFor("smtps-other", "other.test");
        try (TestSmtpServer server = TestSmtpServer.implicitTls(other)) {
            final DeliveryResult r = new SmtpEmailDriver(DeploymentProfile.production(),
                    rebinding("smtps-pin-probe.invalid", server.port(), new AtomicInteger()), Set.of(server.port()))
                    .deliver(provider("smtps-pin-probe.invalid", server.port(),
                            Map.of("tlsMode", "IMPLICIT", "caBundle", other.caPem())), message());
            assertThat(r.status()).isNotEqualTo(Status.ACCEPTED);
            assertThat(server.received()).isEmpty();
        }
    }

    @Test
    void startTlsWithAnUnresolvableNameStillUsesTheValidatedAddress() throws Exception {
        final String name = "smtp-pin-probe.invalid";
        final TestTls tls = TestTls.createFor("smtp-pin", name);
        try (TestSmtpServer server = TestSmtpServer.startTls(tls)) {
            final AtomicInteger lookups = new AtomicInteger();
            final DeliveryResult r = new SmtpEmailDriver(DeploymentProfile.production(),
                    rebinding(name, server.port(), lookups), Set.of(server.port()))
                    .deliver(provider(name, server.port(),
                            Map.of("tlsMode", "STARTTLS_REQUIRED", "caBundle", tls.caPem())), message());
            assertThat(r.status()).as(String.valueOf(r)).isEqualTo(Status.ACCEPTED);
            assertThat(lookups).hasValue(1);
        }
    }
}
