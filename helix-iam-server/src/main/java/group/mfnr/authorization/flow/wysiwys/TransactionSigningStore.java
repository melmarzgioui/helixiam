package group.mfnr.authorization.flow.wysiwys;

import java.util.Optional;

/**
 * Helix IAM E4.4: store for WYSIWYS transaction-signing requests, keyed by id. Shared across
 * publisher instances (the RP starts + polls on one node while the phone signs on another), so a
 * Redis-backed impl drops in for scale; in-process {@link InMemoryTransactionSigningStore} is default.
 */
public interface TransactionSigningStore {

    void save(SignedTransaction transaction);

    Optional<SignedTransaction> find(String id);

    void remove(String id);
}
