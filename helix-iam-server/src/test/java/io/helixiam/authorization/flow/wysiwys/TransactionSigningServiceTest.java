package io.helixiam.authorization.flow.wysiwys;

import io.helixiam.authorization.flow.authenticators.CredentialVerifier;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E4.4: TransactionSigningService builds a canonical WYSIWYS challenge, then verifies the
 * device signature over the EXACT canonical bytes (dynamic linking) via the device Credential SPI,
 * bound to the transaction's stored user (never request input — the E4.3 IDOR lesson).
 */
class TransactionSigningServiceTest {

    private static final long TTL = 120_000L;

    private final InMemoryTransactionSigningStore store = new InMemoryTransactionSigningStore();
    private final Deque<String> tokens = new ArrayDeque<>();
    private final AtomicLong now = new AtomicLong(0);

    private TransactionSigningService service(final CredentialVerifier verifier) {
        return new TransactionSigningService(store, verifier, tokens::removeFirst, now::get, TTL);
    }

    @Test
    void create_buildsCanonicalChallengeWithNonceAndExpiry_andStores() {
        tokens.add("tx-1");
        tokens.add("nonce-1");
        final SignedTransaction tx = service((t, u, i) -> true)
                .create("user-7", "payment", Map.of("amount", "100.00", "to", "NL00BANK"));

        assertThat(tx.id()).isEqualTo("tx-1");
        assertThat(tx.canonicalChallenge())
                .isEqualTo(WysiwysCanonicalizer.canonicalize("payment",
                        Map.of("amount", "100.00", "to", "NL00BANK"), "nonce-1", TTL)); // expiry = now(0)+TTL
        assertThat(store.find("tx-1")).isPresent();
    }

    @Test
    void sign_verifiesDeviceOverCanonicalBytesBoundToTheStoredUser() {
        tokens.add("tx-1");
        tokens.add("nonce-1");
        final AtomicReference<String> sentUser = new AtomicReference<>();
        final AtomicReference<String> sentInput = new AtomicReference<>();
        final TransactionSigningService service = service((type, userId, input) -> {
            sentUser.set(userId);
            sentInput.set(input);
            return true;
        });
        final SignedTransaction tx = service.create("user-7", "payment", Map.of("amount", "5"));

        assertThat(service.sign("tx-1", "device-1", "c2ln")).isTrue();
        assertThat(store.find("tx-1").orElseThrow().status()).isEqualTo(SignedTransaction.Status.SIGNED);
        assertThat(sentUser.get()).isEqualTo("user-7"); // bound to the stored tx user, not request input
        final String expectedChallenge = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(tx.canonicalChallenge().getBytes(StandardCharsets.UTF_8));
        assertThat(sentInput.get()).contains("device-1").contains(expectedChallenge).contains("c2ln");
    }

    @Test
    void sign_badSignature_doesNotSign() {
        tokens.add("tx-1");
        tokens.add("nonce-1");
        final TransactionSigningService service = service((t, u, i) -> false);
        service.create("user-7", "payment", Map.of("amount", "5"));

        assertThat(service.sign("tx-1", "device-1", "c2ln")).isFalse();
        assertThat(store.find("tx-1").orElseThrow().status()).isEqualTo(SignedTransaction.Status.PENDING);
    }

    @Test
    void sign_afterExpiry_fails() {
        tokens.add("tx-1");
        tokens.add("nonce-1");
        final TransactionSigningService service = service((t, u, i) -> true);
        service.create("user-7", "payment", Map.of("amount", "5"));

        now.set(TTL); // reach expiry
        assertThat(service.sign("tx-1", "device-1", "c2ln")).isFalse();
        assertThat(store.find("tx-1").orElseThrow().status()).isEqualTo(SignedTransaction.Status.EXPIRED);
    }

    @Test
    void consume_returnsTheUserOnce() {
        tokens.add("tx-1");
        tokens.add("nonce-1");
        final TransactionSigningService service = service((t, u, i) -> true);
        service.create("user-7", "payment", Map.of("amount", "5"));
        service.sign("tx-1", "device-1", "c2ln");

        assertThat(service.consume("tx-1")).isEqualTo("user-7");
        assertThat(service.consume("tx-1")).isNull();
    }

    @Test
    void sign_unknownTransaction_fails() {
        assertThat(service((t, u, i) -> true).sign("ghost", "device-1", "c2ln")).isFalse();
    }
}
