package io.helixiam.authorization.flow.device;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E4.1 (deferred): device enrollment is authorized by a short-lived, single-use ticket the
 * logged-in user mints; the phone presents it to enroll. The ticket binds the user server-side, so a
 * phone cannot enroll itself to an arbitrary account, and carries the attestation nonce.
 */
class DeviceEnrollmentTicketTest {

    private static final long TTL = 300_000L;

    private DeviceEnrollmentTicket ticket(final long createdAt) {
        return new DeviceEnrollmentTicket("ticket-1", "user-7", "nonce-1", createdAt, TTL);
    }

    @Test
    void startsPendingWithItsUserAndNonce() {
        final DeviceEnrollmentTicket t = ticket(0);
        assertThat(t.status()).isEqualTo(DeviceEnrollmentTicket.Status.PENDING);
        assertThat(t.userId()).isEqualTo("user-7");
        assertThat(t.nonce()).isEqualTo("nonce-1");
    }

    @Test
    void claimReturnsTheUserOnceThenIsSingleUse() {
        final DeviceEnrollmentTicket t = ticket(0);
        assertThat(t.claim(1_000)).isEqualTo("user-7");
        assertThat(t.status()).isEqualTo(DeviceEnrollmentTicket.Status.USED);
        assertThat(t.claim(1_000)).isNull();
    }

    @Test
    void claimAfterTtlExpiresAndYieldsNothing() {
        final DeviceEnrollmentTicket t = ticket(0);
        assertThat(t.claim(TTL)).isNull();
        assertThat(t.status()).isEqualTo(DeviceEnrollmentTicket.Status.EXPIRED);
    }
}
