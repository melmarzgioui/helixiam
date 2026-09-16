package io.helixiam.authorization.flow.qr;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/** Helix IAM E4.2: the default in-process QR session store (single-instance/dev; a Redis-backed
 * impl drops in for horizontal scale via the same interface). */
class InMemoryQrSessionStoreTest {

    private final InMemoryQrSessionStore store = new InMemoryQrSessionStore();

    @Test
    void savesAndFindsById() {
        final QrSession s = new QrSession("a", 0, 300_000, 30_000, "tok");
        store.save(s);

        assertThat(store.find("a")).containsSame(s);
    }

    @Test
    void missingIdIsEmpty() {
        assertThat(store.find("nope")).isEmpty();
    }

    @Test
    void removesById() {
        store.save(new QrSession("a", 0, 300_000, 30_000, "tok"));
        store.remove("a");
        assertThat(store.find("a")).isEmpty();
    }
}
