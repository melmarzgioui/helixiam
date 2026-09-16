package io.helixiam.authorization.flow.qr;

import io.helixiam.authorization.flow.authenticators.CredentialVerifier;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Deque;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E4.2: QrLoginService orchestrates the QR session lifecycle over a store and verifies the
 * phone's confirmation through the generic device Credential SPI (ES256 over the rotating token).
 */
class QrLoginServiceTest {

    private static final long TTL = 300_000L;
    private static final long ROTATE = 30_000L;

    private final InMemoryQrSessionStore store = new InMemoryQrSessionStore();
    private final AtomicLong now = new AtomicLong(0);
    private final Deque<String> tokens = new ArrayDeque<>();

    private QrLoginService service(final CredentialVerifier verifier) {
        return new QrLoginService(store, verifier, tokens::removeFirst, now::get, TTL, ROTATE);
    }

    @Test
    void open_createsPendingSessionWithDistinctIdAndToken() {
        tokens.add("id-1");
        tokens.add("tok-1");
        final QrSession s = service((t, u, i) -> true).open();

        assertThat(s.id()).isEqualTo("id-1");
        assertThat(s.currentToken()).isEqualTo("tok-1");
        assertThat(s.status()).isEqualTo(QrSession.Status.PENDING);
        assertThat(store.find("id-1")).isPresent();
    }

    @Test
    void confirm_verifiesTheDeviceUnderDeviceTypeThenConfirms() {
        tokens.add("id-1");
        tokens.add("tok-1");
        final AtomicReference<String> sentType = new AtomicReference<>();
        final AtomicReference<String> sentInput = new AtomicReference<>();
        final QrLoginService service = service((type, userId, input) -> {
            sentType.set(type);
            sentInput.set(input);
            return true;
        });
        service.open();

        final boolean ok = service.confirm("id-1", "tok-1", "user-7", "device-1", "c2ln");

        assertThat(ok).isTrue();
        assertThat(store.find("id-1").orElseThrow().status()).isEqualTo(QrSession.Status.CONFIRMED);
        assertThat(sentType.get()).isEqualTo("device");
        // the device signs the rotating token; the service packs it as the base64url challenge
        final String expectedChallenge = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("tok-1".getBytes(StandardCharsets.UTF_8));
        assertThat(sentInput.get()).contains("device-1").contains(expectedChallenge).contains("c2ln");
    }

    @Test
    void confirm_isRejectedWhenDeviceVerificationFails() {
        tokens.add("id-1");
        tokens.add("tok-1");
        final QrLoginService service = service((t, u, i) -> false);
        service.open();

        assertThat(service.confirm("id-1", "tok-1", "user-7", "device-1", "c2ln")).isFalse();
        assertThat(store.find("id-1").orElseThrow().status()).isEqualTo(QrSession.Status.PENDING);
    }

    @Test
    void confirm_isRejectedForAnUnknownSession() {
        assertThat(service((t, u, i) -> true).confirm("ghost", "x", "u", "d", "s")).isFalse();
    }

    @Test
    void consume_returnsTheUserOnce() {
        tokens.add("id-1");
        tokens.add("tok-1");
        final QrLoginService service = service((t, u, i) -> true);
        service.open();
        service.confirm("id-1", "tok-1", "user-7", "device-1", "c2ln");

        assertThat(service.consume("id-1")).isEqualTo("user-7");
        assertThat(service.consume("id-1")).isNull();
    }

    @Test
    void refresh_rotatesTheTokenAfterTheInterval() {
        tokens.add("id-1");
        tokens.add("tok-1");
        final QrLoginService service = service((t, u, i) -> true);
        service.open();

        now.set(ROTATE);
        tokens.add("tok-2");
        final QrSession refreshed = service.refresh("id-1").orElseThrow();

        assertThat(refreshed.currentToken()).isEqualTo("tok-2");
    }
}
