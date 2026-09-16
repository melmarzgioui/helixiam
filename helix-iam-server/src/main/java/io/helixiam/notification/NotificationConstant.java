package io.helixiam.notification;

/**
 * Vendored from group.mfnr.subscriber.starter.notification.NotificationConstant.
 * Deviation: dropped the AMQP routing constants (VIRTUALHOST_NOTIFICATION, EXCHANGE_NOTIFICATION,
 * NOTIFICATION_*_ROUTING) since there is no broker to route through anymore; a Notifier
 * implementation dispatches on NotificationRequest.getType()/mediaType directly instead. See
 * VENDOR-MAP.md.
 */
public class NotificationConstant {

    public static final String MODULE_NAME = "Notifications";

    public static final String IDENTIFIER = "IDENTIFIER";
    public static final String DEVICE_ID = "DEVICE_ID";
    public static final String MOBILE_PHONE = "MOBILE_PHONE";
    public static final String EMAIL = "EMAIL";

    private NotificationConstant() {
        throw new IllegalAccessError();
    }
}
