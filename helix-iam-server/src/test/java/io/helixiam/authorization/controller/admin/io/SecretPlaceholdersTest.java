package io.helixiam.authorization.controller.admin.io;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Helix IAM: env-var placeholder derivation + resolution for realm-export secrets. Export emits
 * {@code ${HELIX_<REALM>_<...>_<FIELD>}} in place of every secret; import resolves it from the environment.
 */
class SecretPlaceholdersTest {

    @Test
    void nameFor_buildsStableUppercaseUnderscoredName() {
        assertThat(SecretPlaceholders.nameFor("gov", "billing", "secret"))
                .isEqualTo("HELIX_GOV_BILLING_SECRET");
    }

    @Test
    void nameFor_sanitisesNonAlphanumericAndCollapsesUnderscores() {
        assertThat(SecretPlaceholders.nameFor("my-realm", "client.id", "client-secret"))
                .isEqualTo("HELIX_MY_REALM_CLIENT_ID_CLIENT_SECRET");
    }

    @Test
    void placeholderFor_wrapsTheNameInDollarBraces() {
        assertThat(SecretPlaceholders.placeholderFor("gov", "google", "clientSecret"))
                .isEqualTo("${HELIX_GOV_GOOGLE_CLIENTSECRET}");
    }

    @Test
    void referencedVar_returnsTheVarOnlyForAWholeStringPlaceholder() {
        assertThat(SecretPlaceholders.referencedVar("${FOO_BAR}")).isEqualTo("FOO_BAR");
        assertThat(SecretPlaceholders.referencedVar("literal")).isNull();
        assertThat(SecretPlaceholders.referencedVar("${A} ${B}")).isNull();
        assertThat(SecretPlaceholders.referencedVar(null)).isNull();
    }

    @Test
    void resolve_substitutesAPresentEnvVar() {
        final Map<String, String> env = Map.of("HELIX_GOV_BILLING_SECRET", "s3cr3t");
        assertThat(SecretPlaceholders.resolve("${HELIX_GOV_BILLING_SECRET}", env::get,
                SecretPlaceholders.MissingPolicy.LEAVE_UNSET)).isEqualTo("s3cr3t");
    }

    @Test
    void resolve_leavesUnsetWhenMissingAndPolicyIsLeaveUnset() {
        assertThat(SecretPlaceholders.resolve("${ABSENT}", k -> null,
                SecretPlaceholders.MissingPolicy.LEAVE_UNSET)).isNull();
    }

    @Test
    void resolve_throwsNamingTheVarWhenMissingAndPolicyIsFail() {
        assertThatThrownBy(() -> SecretPlaceholders.resolve("${ABSENT}", k -> null,
                SecretPlaceholders.MissingPolicy.FAIL))
                .isInstanceOf(SecretPlaceholders.MissingSecretException.class)
                .hasMessageContaining("ABSENT");
    }

    @Test
    void resolve_passesLiteralsThroughUnchanged() {
        assertThat(SecretPlaceholders.resolve("not-a-placeholder", k -> "ignored",
                SecretPlaceholders.MissingPolicy.FAIL)).isEqualTo("not-a-placeholder");
        assertThat(SecretPlaceholders.resolve(null, k -> "x",
                SecretPlaceholders.MissingPolicy.FAIL)).isNull();
    }
}
