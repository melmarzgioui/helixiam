/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import io.helixiam.authorization.messaging.email.EmailAddress;
import io.helixiam.authorization.messaging.email.EmailMessage;
import io.helixiam.testsupport.LogCapture;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The LOG driver (development) records that an email was not sent, but never its subject or body: a template may put
 * a one-time code or a link in either (CodeQL java/sensitive-log #280).
 */
class LogEmailDriverTest {

    @Test
    void logsTheMessageIdAndRecipientCount_neverTheSubjectOrBody() {
        final EmailMessage message = new EmailMessage("msg-1", EmailAddress.of("no-reply@example.com"),
                List.of(EmailAddress.of("user@example.org")), null, "Your code is 482913",
                "<p>Code 482913</p>", "Code 482913", Map.of(), null);
        try (LogCapture logs = LogCapture.of(LogEmailDriver.class)) {
            new LogEmailDriver().deliver(null, message);
            assertThat(logs.text()).contains("msg-1").contains("1 recipient")
                    .doesNotContain("482913").doesNotContain("Your code").doesNotContain("user@example.org");
        }
    }
}
