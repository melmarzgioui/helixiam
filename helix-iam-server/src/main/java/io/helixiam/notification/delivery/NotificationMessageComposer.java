package io.helixiam.notification.delivery;

import io.helixiam.notification.domain.NotificationRequest;

/**
 * Task 4 (strip-RabbitMQ notification delivery). Builds the subject/body sent for one
 * {@link NotificationRequest}, keyed off {@link NotificationRequest#getType()} (the {@code type()} of
 * the {@code @Notification} annotation that fired {@code io.helixiam.notification.aop.NotificationAspect}
 * — e.g. {@code USER_SIGNUP}, {@code USER_RESET_PASSWORD} in {@code io.helixiam.authorization.service.UserService}).
 * Unknown types fall back to a generic message so a future {@code @Notification(type = "...")} call
 * site works without touching this class. Pure + side-effect-free, so it is unit-testable without any
 * delivery infrastructure.
 */
public final class NotificationMessageComposer {

    private NotificationMessageComposer() {
    }

    /** One rendered notification: an email/push title and a body. */
    public record ComposedMessage(String subject, String body) {
    }

    public static ComposedMessage compose(final NotificationRequest notification) {
        final String type = notification.getType();
        final String code = notification.getNotificationCode() != null ? notification.getNotificationCode().getCode() : null;

        return switch (type == null ? "" : type) {
            case "USER_SIGNUP" -> new ComposedMessage(
                    "Welcome to HelixIAM — verify your account",
                    "Thanks for signing up. Your verification code is: " + orBlank(code)
                            + "\n\nIf you didn't create this account, you can safely ignore this message.");
            case "USER_RESET_PASSWORD" -> new ComposedMessage(
                    "Reset your HelixIAM password",
                    "We received a request to reset your password. Your reset code is: " + orBlank(code)
                            + "\n\nIf you didn't request this, you can safely ignore this message.");
            default -> new ComposedMessage(
                    "HelixIAM notification" + (type == null || type.isBlank() ? "" : ": " + type),
                    code != null ? "Your code is: " + code : "You have a new notification.");
        };
    }

    private static String orBlank(final String value) {
        return value == null ? "" : value;
    }
}
