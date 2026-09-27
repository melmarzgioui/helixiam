/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The rendered-message model: always a text part with the links, safe headers only, a stable id. */
class EmailMessageTest {

    @Test
    void anHtmlEmailWithoutText_getsATextPartWithEveryLink() {
        final EmailMessage m = EmailMessage.of(null, "ada@example.org", "Verify",
                "<p>Hi</p><p><a href=\"https://idp.example.com/verify?t=1&amp;x=2\">Verify</a></p>", true, null);

        assertThat(m.text()).contains("https://idp.example.com/verify?t=1&x=2").doesNotContain("<");
        assertThat(m.isHtml()).isTrue();
    }

    @Test
    void onlyAllowedHeaders_withoutLineBreaks() {
        assertThatThrownBy(() -> new EmailMessage("id", null, List.of(EmailAddress.of("a@example.org")), null, "s",
                null, "t", Map.of("Bcc", "x@example.org"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new EmailMessage("id", null, List.of(EmailAddress.of("a@example.org")), null, "s",
                null, "t", Map.of("List-Unsubscribe", "<https://x>\r\nBcc: y"))).isInstanceOf(IllegalArgumentException.class);
        assertThat(new EmailMessage("id", null, List.of(EmailAddress.of("a@example.org")), null, "s\r\nBcc: y", null,
                "t", Map.of("List-Unsubscribe", "<https://example.com/u>")).subject()).isEqualTo("s Bcc: y");
        assertThatThrownBy(() -> EmailAddress.of("a@example.org", "A\nB")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theDefaultFromIsTheProvidersFromAddress_andTheIdIsKept() {
        final EmailMessage m = EmailMessage.of(null, "ada@example.org", "s", "t", false, null);
        final EmailMessage filled = m.withDefaultFrom("no-reply@example.com", "Example");

        assertThat(filled.from()).isEqualTo(EmailAddress.of("no-reply@example.com", "Example"));
        assertThat(filled.messageId()).isEqualTo(m.messageId());
        assertThat(EmailMessage.of(null, "ada@example.org", "s", "t", false, null).messageId())
                .isNotEqualTo(m.messageId());
    }
}
