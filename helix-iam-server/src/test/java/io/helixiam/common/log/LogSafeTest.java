/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.log;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** CodeQL java/log-injection: {@link LogSafe} must neutralise every line break and control character. */
class LogSafeTest {

    @Test
    void null_stays_null() {
        assertThat(LogSafe.sanitize((String) null)).isNull();
        assertThat(LogSafe.sanitize((Object) null)).isNull();
    }

    @Test
    void normal_text_is_unchanged() {
        assertThat(LogSafe.sanitize("alice@example.com")).isEqualTo("alice@example.com");
        assertThat(LogSafe.sanitize("realm-1 / client_42 (Ünïcødé, 日本語)"))
                .isEqualTo("realm-1 / client_42 (Ünïcødé, 日本語)");
        assertThat(LogSafe.sanitize("")).isEmpty();
    }

    @Test
    void carriage_return_is_replaced() {
        assertThat(LogSafe.sanitize("a\rb")).isEqualTo("a_b");
    }

    @Test
    void line_feed_is_replaced() {
        assertThat(LogSafe.sanitize("a\nb")).isEqualTo("a_b");
    }

    @Test
    void crlf_is_replaced_and_cannot_forge_a_line() {
        final String forged = LogSafe.sanitize("bob\r\n2026-01-01 INFO Admin login succeeded for root");
        assertThat(forged).isEqualTo("bob_2026-01-01 INFO Admin login succeeded for root");
        assertThat(forged).doesNotContain("\r", "\n");
    }

    @Test
    void other_line_separators_are_replaced() {
        assertThat(LogSafe.sanitize("a\u000Bb\fc\u0085d e f")).isEqualTo("a_b_c_d_e_f");
    }

    @Test
    void tab_and_other_control_characters_are_replaced() {
        assertThat(LogSafe.sanitize("a\tb\u0000c\u001B[31md\u007Fe\u009Bf")).isEqualTo("a_b_c_[31md_e_f");
    }

    @Test
    void non_string_values_are_rendered_then_sanitised() {
        final UUID id = UUID.fromString("00000000-0000-0000-0000-000000000001");
        assertThat(LogSafe.sanitize((Object) id)).isEqualTo(id.toString());
        assertThat(LogSafe.sanitize((Object) 42)).isEqualTo("42");
        assertThat(LogSafe.sanitize(List.of("x\ny", "z"))).isEqualTo("[x_y, z]");
    }
}
