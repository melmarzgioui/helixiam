package io.helixiam.authorization.flow.wysiwys;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E4.4: WYSIWYS dynamic linking hinges on a canonical, length-prefixed encoding of the
 * transaction. The server and the phone must derive byte-identical challenges from the same fields,
 * and no two distinct field sets may collide — otherwise an attacker could get a signature over one
 * transaction and replay it as another. These tests pin that contract.
 */
class WysiwysCanonicalizerTest {

    @Test
    void isDeterministicAndIndependentOfParamInsertionOrder() {
        final Map<String, String> a = new LinkedHashMap<>();
        a.put("amount", "100.00");
        a.put("to", "NL00BANK");
        final Map<String, String> b = new TreeMap<>();
        b.put("to", "NL00BANK");
        b.put("amount", "100.00");

        final String ca = WysiwysCanonicalizer.canonicalize("payment", a, "nonce-1", 1_000L);
        final String cb = WysiwysCanonicalizer.canonicalize("payment", b, "nonce-1", 1_000L);

        assertThat(ca).isEqualTo(cb);
    }

    @Test
    void includesActionParamsNonceAndExpiry() {
        final String c = WysiwysCanonicalizer.canonicalize(
                "payment", Map.of("amount", "100.00", "to", "NL00BANK"), "nonce-1", 1_700_000_000_000L);

        assertThat(c).contains("payment").contains("amount").contains("100.00")
                .contains("to").contains("NL00BANK").contains("nonce-1").contains("1700000000000");
    }

    @Test
    void lengthPrefixingPreventsFieldBoundaryCollisions() {
        // Without length prefixes these two would serialize to the same bytes ("...amount=10to=0ab"
        // vs "amount=1,to=00ab"); the canonical form must keep them distinct.
        final String c1 = WysiwysCanonicalizer.canonicalize("p", Map.of("amount", "10", "to", "0ab"), "n", 1L);
        final String c2 = WysiwysCanonicalizer.canonicalize("p", Map.of("amount", "1", "to", "00ab"), "n", 1L);

        assertThat(c1).isNotEqualTo(c2);
    }

    @Test
    void differentNonceOrExpiryChangesTheChallenge() {
        final Map<String, String> p = Map.of("amount", "5");
        assertThat(WysiwysCanonicalizer.canonicalize("p", p, "n1", 1L))
                .isNotEqualTo(WysiwysCanonicalizer.canonicalize("p", p, "n2", 1L));
        assertThat(WysiwysCanonicalizer.canonicalize("p", p, "n1", 1L))
                .isNotEqualTo(WysiwysCanonicalizer.canonicalize("p", p, "n1", 2L));
    }
}
