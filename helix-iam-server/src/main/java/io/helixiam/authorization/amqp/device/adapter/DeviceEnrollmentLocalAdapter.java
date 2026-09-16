/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.device.adapter;

import io.helixiam.authorization.amqp.device.DeviceEnrollment;
import io.helixiam.authorization.amqp.device.DeviceEnrollmentPublisher;
import io.helixiam.authorization.service.device.DeviceCredentialService;
import org.springframework.stereotype.Component;

import java.util.Base64;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link DeviceEnrollmentPublisher}. Reproduces the former listener's Base64URL decoding of the wire
 * fields before handing them to the device service.
 */
@Component
public class DeviceEnrollmentLocalAdapter implements DeviceEnrollmentPublisher {

    private final DeviceCredentialService deviceService;

    public DeviceEnrollmentLocalAdapter(final DeviceCredentialService deviceService) {
        this.deviceService = deviceService;
    }

    @Override
    public Boolean enroll(final DeviceEnrollment enrollment) {
        return deviceService.enroll(
                enrollment.getUserId(),
                enrollment.getDeviceId(),
                Base64.getUrlDecoder().decode(enrollment.getPublicKey()),
                enrollment.getPlatform(),
                decode(enrollment.getAttestation()),
                decode(enrollment.getNonce()),
                enrollment.isBiometric());
    }

    private static byte[] decode(final String b64Url) {
        return b64Url == null || b64Url.isEmpty() ? new byte[0] : Base64.getUrlDecoder().decode(b64Url);
    }
}
