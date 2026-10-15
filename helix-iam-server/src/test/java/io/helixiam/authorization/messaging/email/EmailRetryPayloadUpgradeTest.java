/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.helixiam.testsupport.Jackson2Fixtures.assertWritesSame;
import static io.helixiam.testsupport.Jackson2Fixtures.read;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Jackson 3 upgrade: an email waiting for a retry at the upgrade ({@code email_retry.payload}) was written by the
 * Jackson 2 line. The current code must send it as it was queued, and queue new ones in the same form.
 */
class EmailRetryPayloadUpgradeTest {

    private final JdbcEmailRetryStore store = new JdbcEmailRetryStore(null, null, null);

    private static JdbcEmailRetryStore.Payload payload() {
        final Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-Helix-Realm", "monthfold");
        headers.put("List-Unsubscribe", "<https://helix.example.eu/u?x=1&y=2>");
        return new JdbcEmailRetryStore.Payload(new EmailAddress("no-reply@example.eu", "Helix / Monthfold"),
                List.of(new EmailAddress("zoe@example.eu", "Zoë Ünal"), new EmailAddress("bob@example.eu", null)),
                null, "Your code: 123 456 \"now\"",
                "<p>Hello Zoë,<br>code <b>123456</b>   😀</p>", "Hello Zoë,\r\ncode 123456\t/ end",
                headers);
    }

    @Test
    void aQueuedEmail_isReadAndWrittenAsBefore() {
        assertWritesSame("email-retry-payload.json", store.write(payload()));

        assertThat(store.read(read("email-retry-payload.json"))).isEqualTo(payload());
    }

    @Test
    void anOlderPayloadWithUnknownMembers_isStillRead() {
        // FAIL_ON_UNKNOWN_PROPERTIES is off for this store: a member a later line adds must not lose the email.
        final JdbcEmailRetryStore.Payload p = store.read("{\"from\":{\"address\":\"a@example.eu\",\"name\":null},"
                + "\"to\":[{\"address\":\"b@example.eu\"}],\"subject\":\"s\",\"text\":\"t\",\"future\":{\"x\":1}}");
        assertThat(p.from().address()).isEqualTo("a@example.eu");
        assertThat(p.to()).extracting(EmailAddress::address).containsExactly("b@example.eu");
        assertThat(p.html()).isNull();
        assertThat(p.headers()).isNull();
    }
}
