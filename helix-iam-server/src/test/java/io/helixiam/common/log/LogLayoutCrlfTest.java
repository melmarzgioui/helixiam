/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.log;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.ConfigurationSource;
import org.apache.logging.log4j.core.config.xml.XmlConfiguration;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Defence in depth for CodeQL java/log-injection: the layouts in {@code log4j2-spring.xml} must escape CR/LF in
 * the log message, so a user-controlled value cannot start a forged log line even if a call site forgot
 * {@link LogSafe}. Parses the real config into a private, never-started context (the test JVM's logging is not
 * touched).
 */
class LogLayoutCrlfTest {

    private static final String FORGED = "bob\r\n2026-01-01 INFO Admin login succeeded for root";

    @Test
    void app_console_layout_escapes_crlf_in_message() throws Exception {
        // Boot sets this only when logging.pattern.console is configured; the in-file default is what ships.
        assumeTrue(System.getProperty("CONSOLE_LOG_PATTERN") == null);
        final String line = render("Console");
        assertSingleLine(line);
        assertThat(line).contains("bob\\r\\n2026-01-01 INFO Admin login succeeded for root");
    }

    @Test
    void audit_console_layout_escapes_crlf_and_keeps_json_unchanged() throws Exception {
        final String line = render("AuditConsole");
        assertSingleLine(line);
        assertThat(line).isEqualTo("user bob\\r\\n2026-01-01 INFO Admin login succeeded for root logged in"
                + System.lineSeparator());

        final String json = "{\"type\":\"LOGIN\",\"user\":\"a\\nb\"}";
        assertThat(renderMessage("AuditConsole", json)).isEqualTo(json + System.lineSeparator());
    }

    private static void assertSingleLine(final String rendered) {
        final String body = rendered.substring(0, rendered.length() - System.lineSeparator().length());
        assertThat(body).doesNotContain("\r", "\n");
    }

    private static String render(final String appender) throws Exception {
        return renderMessage(appender, new ParameterizedMessage("user {} logged in", FORGED).getFormattedMessage());
    }

    private static String renderMessage(final String appenderName, final String message) throws Exception {
        final URL url = LogLayoutCrlfTest.class.getClassLoader().getResource("log4j2-spring.xml");
        assertThat(url).isNotNull();
        final LoggerContext context = new LoggerContext("log-layout-crlf-test");
        try (InputStream in = url.openStream()) {
            final Configuration config = new XmlConfiguration(context, new ConfigurationSource(in, url));
            config.initialize();
            final Appender appender = config.getAppender(appenderName);
            assertThat(appender).as(appenderName).isNotNull();
            final LogEvent event = Log4jLogEvent.newBuilder()
                    .setLoggerName("test")
                    .setLevel(Level.INFO)
                    .setMessage(new org.apache.logging.log4j.message.SimpleMessage(message))
                    .build();
            final byte[] bytes = appender.getLayout().toByteArray(event);
            return new String(bytes, StandardCharsets.UTF_8);
        } finally {
            context.stop();
        }
    }
}
