package group.mfnr.authorization.service.agent;

import group.mfnr.authorization.service.agent.OwnerIntegrity.OwnerStatus;
import group.mfnr.authorization.service.agent.OwnerIntegrity.RealmUser;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An agent's {@code owner} names an accountable human. Owner integrity classifies whether that human is a
 * real, live user of the realm — so orphaned ("zombie owner") and fictional owners surface for review.
 */
class OwnerIntegrityTest {

    private static final List<RealmUser> USERS = List.of(
            new RealmUser("alice", "alice@acme.example", true),
            new RealmUser("bob", "bob@acme.example", false)); // bob is disabled

    @Test
    void ownerMatchingAnEnabledUserIsValid() {
        assertThat(OwnerIntegrity.classify("alice", USERS)).isEqualTo(OwnerStatus.VALID);
        assertThat(OwnerIntegrity.classify("alice@acme.example", USERS)).isEqualTo(OwnerStatus.VALID);
    }

    @Test
    void ownerMatchingADisabledUserIsOrphaned() {
        // The zombie owner: the field still names bob, but bob has been deprovisioned.
        assertThat(OwnerIntegrity.classify("bob", USERS)).isEqualTo(OwnerStatus.ORPHANED);
        assertThat(OwnerIntegrity.classify("bob@acme.example", USERS)).isEqualTo(OwnerStatus.ORPHANED);
    }

    @Test
    void ownerMatchingNoUserIsUnknown() {
        assertThat(OwnerIntegrity.classify("carol@acme.example", USERS)).isEqualTo(OwnerStatus.UNKNOWN);
        assertThat(OwnerIntegrity.classify("", USERS)).isEqualTo(OwnerStatus.UNKNOWN);
        assertThat(OwnerIntegrity.classify(null, USERS)).isEqualTo(OwnerStatus.UNKNOWN);
    }

    @Test
    void matchingIsCaseAndWhitespaceInsensitive() {
        assertThat(OwnerIntegrity.classify("  ALICE@ACME.EXAMPLE ", USERS)).isEqualTo(OwnerStatus.VALID);
        assertThat(OwnerIntegrity.classify("Alice", USERS)).isEqualTo(OwnerStatus.VALID);
    }
}
