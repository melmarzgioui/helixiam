package group.mfnr.authorization.flow.push;

import group.mfnr.authorization.flow.authenticators.CredentialVerifier;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Deque;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.IntSupplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E4.3: PushApprovalService starts a number-matching approval, sends it via the PushSender,
 * and resolves the phone's response — requiring BOTH a valid device signature (device Credential SPI)
 * AND the matching number. A bad signature is rejected without changing state; a wrong number denies.
 */
class PushApprovalServiceTest {

    private static final long TTL = 120_000L;

    private final InMemoryPushApprovalStore store = new InMemoryPushApprovalStore();
    private final Deque<String> tokens = new ArrayDeque<>();
    private final Deque<Integer> numbers = new ArrayDeque<>();
    private final AtomicReference<PushMessage> sent = new AtomicReference<>();
    private final PushSender sender = sent::set;

    private PushApprovalService service(final CredentialVerifier verifier) {
        final IntSupplier numberGen = numbers::removeFirst;
        return new PushApprovalService(store, verifier, sender, tokens::removeFirst, numberGen, () -> 0L, TTL);
    }

    @Test
    void start_createsPendingAndPushesTheNumberMatchChoices() {
        tokens.add("id-1");
        tokens.add("nonce-1");
        numbers.add(42); // expected
        numbers.add(13);
        numbers.add(77);

        final PushApproval a = service((t, u, i) -> true).start("user-7");

        assertThat(a.expectedNumber()).isEqualTo(42);
        assertThat(a.status()).isEqualTo(PushApproval.Status.PENDING);
        assertThat(store.find("id-1")).isPresent();
        assertThat(sent.get().approvalId()).isEqualTo("id-1");
        assertThat(sent.get().expectedNumber()).isEqualTo(42);
        assertThat(sent.get().candidates()).contains(42, 13, 77).hasSize(3);
    }

    @Test
    void approve_requiresDeviceSignatureThenMatchingNumber() {
        tokens.add("id-1");
        tokens.add("nonce-1");
        numbers.add(42);
        numbers.add(13);
        numbers.add(77);
        final AtomicReference<String> sentType = new AtomicReference<>();
        final AtomicReference<String> sentUser = new AtomicReference<>();
        final AtomicReference<String> sentInput = new AtomicReference<>();
        final PushApprovalService service = service((type, userId, input) -> {
            sentType.set(type);
            sentUser.set(userId);
            sentInput.set(input);
            return true;
        });
        service.start("user-7");

        assertThat(service.approve("id-1", 42, "device-1", "c2ln")).isTrue();
        assertThat(store.find("id-1").orElseThrow().status()).isEqualTo(PushApproval.Status.APPROVED);
        assertThat(sentType.get()).isEqualTo("device");
        // device verification is bound to the approval's user, never a client-supplied one (IDOR fix)
        assertThat(sentUser.get()).isEqualTo("user-7");
        final String expectedChallenge = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("nonce-1".getBytes(StandardCharsets.UTF_8));
        assertThat(sentInput.get()).contains("device-1").contains(expectedChallenge).contains("c2ln");
    }

    @Test
    void approve_alwaysVerifiesAgainstTheApprovalsBoundUser() {
        tokens.add("id-1");
        tokens.add("nonce-1");
        numbers.add(42);
        numbers.add(13);
        numbers.add(77);
        // A verifier that only accepts the victim's id proves a foreign device (any other id) can't approve.
        final PushApprovalService service = service((type, userId, input) -> "user-7".equals(userId));
        service.start("user-7");

        // The phone supplies only number + deviceId + signature; the user is the approval's, so an
        // attacker's enrolled device (which would verify under a different id) gets no say here.
        assertThat(service.approve("id-1", 42, "attacker-device", "c2ln")).isTrue();
    }

    @Test
    void approve_wrongNumber_denies() {
        tokens.add("id-1");
        tokens.add("nonce-1");
        numbers.add(42);
        numbers.add(13);
        numbers.add(77);
        final PushApprovalService service = service((t, u, i) -> true);
        service.start("user-7");

        assertThat(service.approve("id-1", 13, "device-1", "c2ln")).isFalse();
        assertThat(store.find("id-1").orElseThrow().status()).isEqualTo(PushApproval.Status.DENIED);
    }

    @Test
    void approve_badDeviceSignature_rejectedWithoutChangingState() {
        tokens.add("id-1");
        tokens.add("nonce-1");
        numbers.add(42);
        numbers.add(13);
        numbers.add(77);
        final PushApprovalService service = service((t, u, i) -> false);
        service.start("user-7");

        assertThat(service.approve("id-1", 42, "device-1", "c2ln")).isFalse();
        assertThat(store.find("id-1").orElseThrow().status()).isEqualTo(PushApproval.Status.PENDING);
    }

    @Test
    void consume_returnsTheUserOnce() {
        tokens.add("id-1");
        tokens.add("nonce-1");
        numbers.add(42);
        numbers.add(13);
        numbers.add(77);
        final PushApprovalService service = service((t, u, i) -> true);
        service.start("user-7");
        service.approve("id-1", 42, "device-1", "c2ln");

        assertThat(service.consume("id-1")).isEqualTo("user-7");
        assertThat(service.consume("id-1")).isNull();
    }
}
