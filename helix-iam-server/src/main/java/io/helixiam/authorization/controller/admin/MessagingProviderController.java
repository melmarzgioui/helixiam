package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.messaging.MessagingAdminPublisher;
import io.helixiam.authorization.amqp.messaging.MessagingProviderDto;
import io.helixiam.authorization.amqp.messaging.MessagingProviderKey;
import io.helixiam.authorization.amqp.messaging.MessagingProviderWriteDto;
import io.helixiam.authorization.messaging.MessagingService;
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
 * returned; the realm always comes from the path.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/messaging/providers")
public class MessagingProviderController {

    private final MessagingAdminPublisher publisher;
    private final MessagingService messaging;

    public MessagingProviderController(final MessagingAdminPublisher publisher, final MessagingService messaging) {
        this.publisher = publisher;
        this.messaging = messaging;
    }

    @GetMapping
    public List<MessagingProviderDto> list(@PathVariable final String realmId) {
        return publisher.listProviders(realmId);
    }

    @PutMapping
    public MessagingProviderDto save(@PathVariable final String realmId,
                                     @Valid @RequestBody final MessagingProviderWriteDto body) {
        // The realm is authoritative from the path — never trust the body's realmId.
        return publisher.saveProvider(new MessagingProviderWriteDto(realmId, body.channel(), body.driver(),
                body.enabled(), body.fromAddress(), body.fromName(), body.config(), body.secret()));
    }

    @DeleteMapping("/{channel}/{driver}")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String channel,
                                       @PathVariable final String driver) {
        return Boolean.TRUE.equals(publisher.deleteProvider(new MessagingProviderKey(realmId, channel, driver)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /** Send a test message through the realm's configured provider for {@code channel} (SMS or EMAIL). */
    @PostMapping("/{channel}/test")
    public TestResult test(@PathVariable final String realmId, @PathVariable final String channel,
                           @RequestBody final TestRequest request) {
        final Map<String, String> vars = new java.util.LinkedHashMap<>(Map.of("realm", realmId, "code", "123456",
                "ttl", "5 minutes", "user", "Test User", "link", "https://helix.example/test", "number", "42"));
        // User-claim passthrough (N6a): sample user.<claim> values so a test-send exercises personalised templates.
        vars.put("user.email", "test.user@example.com");
        vars.put("user.given_name", "Test");
        vars.put("user.preferred_username", "test.user");
        try {
            final boolean sent;
            if ("PUSH".equalsIgnoreCase(channel)) {
                // The recipient is a device token; tag it for both platforms so it routes to whichever push
                // provider (FCM / APNs) the realm has enabled.
                final List<io.helixiam.authorization.amqp.messaging.DevicePushTokenDto> tokens = List.of(
                        new io.helixiam.authorization.amqp.messaging.DevicePushTokenDto(realmId, "test-user", "FCM", request.to()),
                        new io.helixiam.authorization.amqp.messaging.DevicePushTokenDto(realmId, "test-user", "APNS", request.to()));
                sent = messaging.sendPush(realmId, tokens, "push-approval", vars,
                        Map.of("approvalId", "test", "challenge", "test", "expectedNumber", "42"));
            } else if ("EMAIL".equalsIgnoreCase(channel)) {
                sent = messaging.sendEmail(realmId, request.to(), "otp-email", vars);
            } else {
                sent = messaging.sendSms(realmId, request.to(), "otp-sms", vars);
            }
            return new TestResult(sent, sent ? "Test message sent." : "No enabled " + channel + " provider for this realm.");
        } catch (final RuntimeException e) {
            return new TestResult(false, "Send failed: " + e.getMessage());
        }
    }

    /** Test-send request: the recipient (phone or email). */
    public record TestRequest(String to) {
    }

    /** Test-send outcome. */
    public record TestResult(boolean sent, String message) {
    }
}
