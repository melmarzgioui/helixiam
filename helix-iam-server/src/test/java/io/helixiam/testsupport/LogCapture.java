/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.testsupport;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Captures the formatted messages one class's Log4j2 logger emits (at every level), for asserting that a
 * secret never reaches the logs. Use in try-with-resources so the appender and level are always restored.
 */
public final class LogCapture implements AutoCloseable {

    private final Logger logger;
    private final Level previousLevel;
    private final AbstractAppender appender;
    private final List<String> messages = new CopyOnWriteArrayList<>();

    private final boolean keepLevel;

    private LogCapture(final Class<?> type) {
        this((Logger) LogManager.getLogger(type), "log-capture-" + type.getSimpleName(), false);
    }

    private LogCapture(final Logger logger, final String name, final boolean keepLevel) {
        this.logger = logger;
        this.keepLevel = keepLevel;
        this.previousLevel = logger == null ? null : logger.getLevel();
        this.appender = new AbstractAppender(name, null, null, true,
                Property.EMPTY_ARRAY) {
            @Override
            public void append(final LogEvent event) {
                messages.add(event.getMessage().getFormattedMessage());
            }
        };
        appender.start();
        if (logger == null) {
            // Root of the live configuration, and refresh every logger's cached config: loggers whose own config was
            // created by an earlier capture in this JVM must still reach the root appender.
            final org.apache.logging.log4j.core.LoggerContext ctx =
                    (org.apache.logging.log4j.core.LoggerContext) LogManager.getContext(false);
            ctx.getConfiguration().getRootLogger().addAppender(appender, null, null);
            ctx.updateLoggers();
            return;
        }
        logger.addAppender(appender);
        if (!keepLevel) {
            logger.setLevel(Level.ALL);
        }
    }

    public static LogCapture of(final Class<?> type) {
        return new LogCapture(type);
    }

    /**
     * Every message any logger emits (through the root logger, at the configured levels), from every thread; for
     * asserting that a secret never reaches the server's logs in an end-to-end test.
     */
    public static LogCapture all() {
        return new LogCapture(null, "log-capture-all", true);
    }

    /** The messages of the logger named {@code name} at its configured level (e.g. the non-additive audit stream). */
    public static LogCapture named(final String name) {
        return new LogCapture((Logger) LogManager.getLogger(name), "log-capture-" + name, true);
    }

    /** Every captured message, joined by newlines. */
    public String text() {
        return String.join("\n", messages);
    }

    public List<String> messages() {
        return List.copyOf(messages);
    }

    @Override
    public void close() {
        if (logger == null) {
            final org.apache.logging.log4j.core.LoggerContext ctx =
                    (org.apache.logging.log4j.core.LoggerContext) LogManager.getContext(false);
            ctx.getConfiguration().getRootLogger().removeAppender(appender.getName());
            ctx.updateLoggers();
            appender.stop();
            return;
        }
        logger.removeAppender(appender);
        if (!keepLevel) {
            logger.setLevel(previousLevel);
        }
        appender.stop();
    }
}
