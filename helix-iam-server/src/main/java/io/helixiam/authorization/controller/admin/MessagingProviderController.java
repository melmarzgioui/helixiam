/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.messaging.MessagingAdminPublisher;
import io.helixiam.authorization.amqp.messaging.MessagingProviderDto;
import io.helixiam.authorization.amqp.messaging.MessagingProviderKey;
import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.amqp.messaging.MessagingProviderWriteDto;
import io.helixiam.authorization.messaging.MessagingService;
import io.helixiam.authorization.messaging.email.DeliveryResult;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM notifications (N2): admin REST API for a realm's messaging providers (SMS / email / push) —
 * the backend behind the console's Authentication → Notifications screen. Secrets are write-only and never
 * returned; the realm always comes from the path. A provider is validated before it is saved
 * ({@link MessagingProviderValidator}; 400 {@code {message, fieldErrors}}).
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/messaging/providers")
public class MessagingProviderController {

    private final MessagingAdminPublisher publisher;
    private final MessagingService messaging;
    private final MessagingProviderValidator validator;

    public MessagingProviderController(final MessagingAdminPublisher publisher, final MessagingService messaging,
                                       final MessagingProviderValidator validator) {
        this.publisher = publisher;
        this.messaging = messaging;
        this.validator = validator;
    }

    @GetMapping
    public List<MessagingProviderDto> list(@PathVariable final String realmId) {
        return publisher.listProviders(realmId);
    }

    @PutMapping
    public MessagingProviderDto save(@PathVariable final String realmId,
                                     @Valid @RequestBody final MessagingProviderWriteDto body) {
        // The realm is authoritative from the path — never trust the body's realmId.
        final MessagingProviderWriteDto write = new MessagingProviderWriteDto(realmId, body.channel(), body.driver(),
                body.enabled(), body.fromAddress(), body.fromName(), body.config(), body.secret(), body.clearSecret());
        final boolean secretStored = publisher.listProviders(realmId).stream().anyMatch(p ->
                p.channel() != null && p.channel().equalsIgnoreCase(body.channel())
                        && p.driver() != null && p.driver().equalsIgnoreCase(body.driver()) && p.secretSet());
        return publisher.saveProvider(validator.validate(write, secretStored));
    }

    @DeleteMapping("/{channel}/{driver}")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String channel,
                                       @PathVariable final String driver) {
        return Boolean.TRUE.equals(publisher.deleteProvider(new MessagingProviderKey(realmId, channel, driver)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /**
     * Send a test message through one of the realm's providers for {@code channel} (SMS, EMAIL or PUSH).
     *
     * <ul>
     *   <li>{@code to}: the recipient (email address, phone number or device token).</li>
     *   <li>{@code driver} (optional): test the realm's provider with that driver, <b>even when it is disabled</b>, so
     *       an operator can check a provider before switching to it. Without it, the realm's enabled (active) provider
     *       is tested. A driver the channel does not know is a 400 ({@code fieldErrors.driver}); a known driver the
     *       realm has not configured answers {@code sent: false}.</li>
     * </ul>
     * For EMAIL a real email goes out once (never retried; the send rate cap applies), and the answer carries its
     * classified {@code result}, {@code reason}, {@code diagnostic}, {@code providerMessageId} and the tested
     * {@code driver}.
     */
    @PostMapping("/{channel}/test")
    public TestResult test(@PathVariable final String realmId, @PathVariable final String channel,
                           @RequestBody final TestRequest request) {
        final Map<String, String> vars = new java.util.LinkedHashMap<>(Map.of("realm", realmId, "code", "123456",
                "ttl", "5 minutes", "user", "Test User", "link", "https://helix.example/test", "number", "42"));
        // User-claim passthrough (N6a): sample user.<claim> values so a test-send exercises personalised templates.
        vars.put("user.email", "test.user@example.com");
        vars.put("user.given_name", "Test");
        vars.put("user.preferred_username", "test.user");
        final String requestedDriver = request == null || request.driver() == null || request.driver().isBlank()
                ? null : request.driver().trim().toUpperCase(java.util.Locale.ROOT);
        ResolvedProviderDto chosen = null;
        if (requestedDriver != null) {
            final java.util.Set<String> known = MessagingProviderValidator.DRIVERS.get(
                    channel.toUpperCase(java.util.Locale.ROOT));
            if (known == null || !known.contains(requestedDriver)) {
                throw new ProviderValidationException(Map.of("driver", "Unknown " + channel.toUpperCase(
                        java.util.Locale.ROOT) + " driver" + (known == null ? "." : ". Use " + String.join(", ",
                        known.stream().sorted().toList()) + ".")));
            }
            chosen = publisher.resolveProvider(new MessagingProviderKey(realmId, channel.toUpperCase(
                    java.util.Locale.ROOT), requestedDriver));
            if (chosen == null) {
                return new TestResult(false, "No " + channel.toUpperCase(java.util.Locale.ROOT) + " provider with driver "
                        + requestedDriver + " is configured for this realm.");
            }
        }
        try {
            final boolean sent;
            if ("PUSH".equalsIgnoreCase(channel)) {
                // The recipient is a device token; tag it for both platforms so it routes to whichever push
                // provider (FCM / APNs) the realm has enabled.
                final List<io.helixiam.authorization.amqp.messaging.DevicePushTokenDto> tokens = List.of(
                        new io.helixiam.authorization.amqp.messaging.DevicePushTokenDto(realmId, "test-user", "FCM", request.to()),
                        new io.helixiam.authorization.amqp.messaging.DevicePushTokenDto(realmId, "test-user", "APNS", request.to()));
                final Map<String, String> data = Map.of("approvalId", "test", "challenge", "test", "expectedNumber", "42");
                sent = chosen == null ? messaging.sendPush(realmId, tokens, "push-approval", vars, data)
                        : messaging.sendPush(realmId, List.of(chosen), tokens, "push-approval", vars, data);
            } else if ("EMAIL".equalsIgnoreCase(channel)) {
                if (request == null || request.to() == null || request.to().isBlank()) {
                    return new TestResult(false, "Enter the email address to send the test to.");
                }
                final java.util.Optional<DeliveryResult> result = messaging.sendEmailWithResult(realmId, chosen,
                        request.to(), "otp-email", vars);
                if (result.isEmpty()) {
                    return new TestResult(false, "No enabled EMAIL provider for this realm.");
                }
                final DeliveryResult r = result.get();
                final String driver = chosen != null ? chosen.driver()
                        : messaging.activeEmailDriver(realmId).orElse(null);
                return new TestResult(r.isSuccess(), r.isSuccess() ? "Test email " + (r.status()
                        == DeliveryResult.Status.QUEUED ? "queued" : "sent") + "." : "Test email not delivered.",
                        r.status().name(), r.reason().name(), r.diagnostic(), r.providerMessageId(), driver);
            } else {
                sent = chosen == null ? messaging.sendSms(realmId, request.to(), "otp-sms", vars)
                        : messaging.sendSms(realmId, chosen, request.to(), "otp-sms", vars);
            }
            return new TestResult(sent, sent ? "Test message sent." : "No enabled " + channel + " provider for this realm.");
        } catch (final RuntimeException e) {
            return new TestResult(false, "Send failed: " + io.helixiam.common.log.LogSafe.sanitize(e.getMessage()));
        }
    }

    /** Test-send request: the recipient (phone, email or device token) and, optionally, the provider's driver. */
    public record TestRequest(String to, String driver) {
    }

    /**
     * Test-send outcome. For EMAIL also the classified {@code result}, its {@code reason}, the safe
     * {@code diagnostic} and the provider's message id (null when the provider returns none).
     */
    @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
    public record TestResult(boolean sent, String message, String result, String reason, String diagnostic,
                             String providerMessageId, String driver) {

        public TestResult(final boolean sent, final String message) {
            this(sent, message, null, null, null, null, null);
        }
    }
}
