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

    private LogCapture(final Class<?> type) {
        this.logger = (Logger) LogManager.getLogger(type);
        this.previousLevel = logger.getLevel();
        this.appender = new AbstractAppender("log-capture-" + type.getSimpleName(), null, null, true,
                Property.EMPTY_ARRAY) {
            @Override
            public void append(final LogEvent event) {
                messages.add(event.getMessage().getFormattedMessage());
            }
        };
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.ALL);
    }

    public static LogCapture of(final Class<?> type) {
        return new LogCapture(type);
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
        logger.removeAppender(appender);
        logger.setLevel(previousLevel);
        appender.stop();
    }
}
