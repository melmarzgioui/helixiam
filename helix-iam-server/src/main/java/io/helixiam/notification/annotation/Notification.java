package io.helixiam.notification.annotation;

import java.lang.annotation.*;

/**
 * Vendored verbatim (package renamed only) from
 * io.helixiam.subscriber.starter.annotation.notification.Notification.
 * Not in the Task 1 file list (it lived in the separate mfnr-subscriber-starter-annotations
 * module); pulled in because io.helixiam.notification.aop.NotificationAspect (on the Task 1
 * list) is driven by it. See VENDOR-MAP.md.
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface Notification {
    NotificationMediaType[] mediaType();

    String overrideIdentifier() default "";
    String overrideEmailAddress() default "";
    String type();

    boolean generateCode() default false;
    boolean generateSimpleCode() default false;
}
