/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.notification.aop;

import io.helixiam.notification.Notifier;
import io.helixiam.notification.NotificationConstant;
import io.helixiam.notification.annotation.Notification;
import io.helixiam.notification.annotation.NotificationEmail;
import io.helixiam.notification.annotation.NotificationIdentifier;
import io.helixiam.notification.annotation.NotificationMediaType;
import io.helixiam.notification.domain.NotificationCode;
import io.helixiam.notification.domain.NotificationRequest;
import io.helixiam.notification.repository.NotificationCodeRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Vendored from io.helixiam.subscriber.starter.notification.aop.NotificationAspect.
 * Deviation: depends on the new io.helixiam.notification.Notifier instead of the AMQP
 * NotificationPublisher; the three dispatch call sites (sendAppNotification/sendEmailNotification/
 * sendSmsNotification) are otherwise unchanged. Also replaced
 * org.apache.commons.lang3.StringUtils.isNotEmpty(identifier) (commons-lang3 is not a
 * helix-iam-server dependency) with an equivalent inline null/empty check. See VENDOR-MAP.md.
 */
@Aspect
@Component
public class NotificationAspect {
    private static final Logger LOG = LogManager.getLogger(NotificationConstant.MODULE_NAME);

    private final Notifier notifier;
    private final NotificationCodeRepository notificationCodeRepository;
    private io.helixiam.notification.NotificationCodePolicy codePolicy =
            io.helixiam.notification.NotificationCodePolicy.defaults();

    private io.helixiam.notification.NotificationCodeIssuer codeIssuer;

    /** Issues the codes (hashed at rest); without one (tests), a default issuer over the repository. */
    @Autowired(required = false)
    public void setCodeIssuer(final io.helixiam.notification.NotificationCodeIssuer codeIssuer) {
        this.codeIssuer = codeIssuer;
    }

    private io.helixiam.notification.NotificationCodeIssuer codeIssuer() {
        if (codeIssuer == null) {
            codeIssuer = new io.helixiam.notification.NotificationCodeIssuer(notificationCodeRepository, codePolicy);
        }
        return codeIssuer;
    }

    /** How long the generated codes work (password reset 1 hour, sign-up 24 hours by default). */
    @Autowired(required = false)
    public void setCodePolicy(final io.helixiam.notification.NotificationCodePolicy codePolicy) {
        if (codePolicy != null) {
            this.codePolicy = codePolicy;
        }
    }

    @Autowired
    public NotificationAspect(final Notifier notifier, final NotificationCodeRepository notificationCodeRepository) {
        this.notifier = notifier;
        this.notificationCodeRepository = notificationCodeRepository;
    }

    @Around("@annotation(notification)")
    public Object proceed(final ProceedingJoinPoint proceedingJoinPoint, final Notification notification) throws Throwable {

        final Object returnValue = proceedingJoinPoint.proceed();

        try {
            buildNotification(notification, returnValue, proceedingJoinPoint).ifPresent(notificationRequest -> {
                for (final NotificationMediaType mediaType : notification.mediaType()) {
                    switch (mediaType) {
                        case APP -> notifier.sendAppNotification(notificationRequest);
                        case EMAIL -> notifier.sendEmailNotification(notificationRequest);
                        case SMS -> notifier.sendSmsNotification(notificationRequest);
                    }
                }
                LOG.debug("Notification send");
            });
        } catch (final Exception exception) {
            LOG.warn("Failed to send notification '{}'", exception.getCause().getMessage());
        }

        return returnValue;
    }

    private Optional<NotificationRequest> buildNotification(final Notification notification, final Object returnObject, final ProceedingJoinPoint proceedingJoinPoint) {
        final Map<String, String> userDetails = getUserDetails(returnObject, proceedingJoinPoint);
        final String identifier = userDetails.get(NotificationConstant.IDENTIFIER);

        if(isNotEmpty(identifier)) {
            final NotificationRequest notificationRequest = new NotificationRequest(notification.type());
            notificationRequest.setDeviceId(userDetails.get("DEVICE_ID"));
            notificationRequest.setMobile(userDetails.get("MOBILE_PHONE"));
            notificationRequest.setEmailAddress(userDetails.get("EMAIL"));

            if (notification.generateCode() || notification.generateSimpleCode()) {
                // A new code on every request; only its SHA-256 is stored (NotificationCodeIssuer).
                final NotificationCode notificationCode = codeIssuer().issue(identifier, notification.type(),
                        notification.generateSimpleCode());
                notificationRequest.setNotificationCode(notificationCode);
            }

            return Optional.of(notificationRequest);
        }

        return Optional.empty();
    }

    private static boolean isNotEmpty(final String value) {
        return value != null && !value.isEmpty();
    }

    private Map<String, String> getUserDetails(final Object returnObject, final ProceedingJoinPoint proceedingJoinPoint) {

        final Signature signature = proceedingJoinPoint.getSignature();
        final Parameter[] parameters = ((MethodSignature) signature).getMethod().getParameters();

        // Notification based on user input
        if(parameters != null) {
            final Map<String, String> userDetails = new HashMap<>();
            for (int i = 0; i < parameters.length; i++) {
                if(parameters[i].getDeclaredAnnotation(NotificationEmail.class) != null) {
                    userDetails.put(NotificationConstant.EMAIL, (String)proceedingJoinPoint.getArgs()[i]);
                }
                if(parameters[i].getDeclaredAnnotation(NotificationIdentifier.class) != null) {
                    userDetails.put(NotificationConstant.IDENTIFIER, (String)proceedingJoinPoint.getArgs()[i]);
                }
            }

            // Need to make fancy later
            if(userDetails.size() == 1 && returnObject != null) {
                findField(returnObject, "userId").ifPresent(field -> {
                    try {
                        field.setAccessible(true);
                        userDetails.put(NotificationConstant.IDENTIFIER, (String) field.get(returnObject));
                    } catch (final IllegalAccessException e) {
                        // swallow
                    }
                });
            }

            // Override NotificationIdentifier but use user email address
            if(userDetails.get(NotificationConstant.IDENTIFIER) != null && userDetails.get(NotificationConstant.EMAIL) == null && SecurityContextHolder.getContext().getAuthentication() != null && SecurityContextHolder.getContext().getAuthentication().getPrincipal() instanceof Jwt jwtToken) {
                userDetails.put(NotificationConstant.EMAIL, jwtToken.getClaim("email"));
            }

            if(userDetails.size() == 2) {
                return userDetails;
            }
        }

        // Notification based on authorized user
        if(SecurityContextHolder.getContext().getAuthentication() != null && SecurityContextHolder.getContext().getAuthentication().getPrincipal() instanceof Jwt jwtToken) {
            final Map<String, String> userDetails = new HashMap<>();
            userDetails.put(NotificationConstant.IDENTIFIER, jwtToken.getSubject());
            userDetails.put(NotificationConstant.DEVICE_ID, jwtToken.getClaim("deviceId"));
            userDetails.put(NotificationConstant.MOBILE_PHONE, jwtToken.getClaim("mobilePhone"));
            userDetails.put(NotificationConstant.EMAIL, jwtToken.getClaim("email"));

            return userDetails;
        }

        return new HashMap<>();
    }


    private Optional<Field> findField(final Object returnObject, final String fieldName) {
        return Arrays.stream(returnObject.getClass().getDeclaredFields()).filter(field -> field.getName().equalsIgnoreCase(fieldName)).findFirst();
    }
}
