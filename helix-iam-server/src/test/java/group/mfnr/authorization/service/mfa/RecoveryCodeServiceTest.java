package group.mfnr.authorization.service.mfa;

import group.mfnr.authorization.domain.mfa.RecoveryCodeEntity;
import group.mfnr.authorization.repository.mfa.RecoveryCodeRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E3.2: generating a set of single-use recovery codes (returning the plaintext once
 * while storing only hashes), and verifying-and-burning a submitted code.
 */
class RecoveryCodeServiceTest {

    private RecoveryCodeRepository repository;
    private RecoveryCodeService service;

    @BeforeEach
    void setUp() {
        repository = mock(RecoveryCodeRepository.class);
        service = new RecoveryCodeService(repository);
        when(repository.save(any(RecoveryCodeEntity.class))).thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void generate_returnsTheRequestedNumberOfDistinctPlaintextCodes() {
        List<String> codes = service.generate("user-1", 8);

        assertThat(codes).hasSize(8).doesNotHaveDuplicates();
        assertThat(codes).allSatisfy(c -> assertThat(c).isNotBlank());
        verify(repository).deleteAllByUserId("user-1"); // regenerating replaces the old set
    }

    @Test
    void generate_storesHashesNotThePlaintext() {
        @SuppressWarnings("unchecked")
        final java.util.concurrent.atomic.AtomicReference<List<RecoveryCodeEntity>> saved =
                new java.util.concurrent.atomic.AtomicReference<>();
        when(repository.saveAll(anyList())).thenAnswer(inv -> {
            saved.set(new ArrayList<>(inv.getArgument(0)));
            return saved.get();
        });

        List<String> codes = service.generate("user-1", 3);

        assertThat(saved.get()).hasSize(3);
        assertThat(saved.get()).extracting(RecoveryCodeEntity::getCodeHash)
                .doesNotContainAnyElementsOf(codes); // hash != plaintext
    }

    @Test
    void verifyAndConsume_validUnusedCode_burnsItAndReturnsTrue() {
        List<String> codes = captureGenerated("user-1", 2);
        String valid = codes.get(0);

        boolean result = service.verifyAndConsume("user-1", valid);

        assertThat(result).isTrue();
        // the matching entity is marked used and saved
        verify(repository).save(any(RecoveryCodeEntity.class));
    }

    @Test
    void verifyAndConsume_unknownCode_returnsFalse_andBurnsNothing() {
        captureGenerated("user-1", 2);

        boolean result = service.verifyAndConsume("user-1", "NOT-A-REAL-CODE");

        assertThat(result).isFalse();
        verify(repository, never()).save(any(RecoveryCodeEntity.class));
    }

    /** Generates codes and wires the repo to return their (unused) stored entities for verify. */
    private List<String> captureGenerated(final String userId, final int count) {
        final List<RecoveryCodeEntity> stored = new ArrayList<>();
        when(repository.saveAll(anyList())).thenAnswer(inv -> {
            stored.addAll(inv.getArgument(0));
            return stored;
        });
        final List<String> codes = service.generate(userId, count);
        when(repository.findAllByUserIdAndUsedFalse(userId)).thenReturn(stored);
        return codes;
    }
}
