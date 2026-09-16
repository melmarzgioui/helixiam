package io.helixiam.authorization.amqp.device;


/**
 * Helix IAM E4.1: device enrollment against the subscriber (which verifies the platform attestation
 * and stores the device's public key) over AMQP. Login/step-up assertions ride the generic
 * credential exchange.
 */
public interface DeviceEnrollmentPublisher {

    String EXCHANGE_AUTHORIZATION_DEVICE = "exchange-authorization-device";
    String DEVICE_ENROLL = "authorization.device.enroll";

    Boolean enroll(DeviceEnrollment enrollment);
}
