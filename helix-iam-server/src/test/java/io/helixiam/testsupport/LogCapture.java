/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.testsupport;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Captures the formatted messages a Log4j2 logger emits, for asserting that a secret never reaches the logs. Use in
 * try-with-resources.
 *
 * <p>It works on the live configuration: it attaches its appender to the logger's own {@link LoggerConfig} (creating
 * one when the logger has none) and, on close, removes the appender and any config it created and restores the level.
 * It never leaves a config behind, so a logger it captured keeps logging normally afterwards (an earlier version set
 * the level on the logger itself, which could leave a stale config that silenced the logger for the rest of the JVM).
 */
public final class LogCapture implements AutoCloseable {

    private final LoggerContext context;
    private final String name;
    private final boolean created;
    private final Level previousLevel;
    private final AbstractAppender appender;
    private final List<String> messages = new CopyOnWriteArrayList<>();

    private LogCapture(final String name, final boolean allLevels) {
        this.context = (LoggerContext) LogManager.getContext(false);
        this.name = name;
        this.appender = new AbstractAppender("log-capture-" + (name.isEmpty() ? "root" : name), null, null, true,
                Property.EMPTY_ARRAY) {
            @Override
            public void append(final LogEvent event) {
                messages.add(event.getMessage().getFormattedMessage());
            }
        };
        appender.start();
        final Configuration config = context.getConfiguration();
        LoggerConfig target = name.isEmpty() ? config.getRootLogger() : config.getLoggers().get(name);
        if (target == null) {
            target = new LoggerConfig(name, null, true);
            config.addLogger(name, target);
            this.created = true;
        } else {
            this.created = false;
        }
        this.previousLevel = target.getExplicitLevel();
        target.addAppender(appender, null, null);
        if (allLevels) {
            target.setLevel(Level.ALL);
        }
        context.updateLoggers();
    }

    /** One class's logger, at every level. */
    public static LogCapture of(final Class<?> type) {
        return new LogCapture(type.getName(), true);
    }

    /**
     * Every message any additive logger emits (through the root logger, at the configured levels), from every thread;
     * for asserting that a secret never reaches the server's logs in an end-to-end test.
     */
    public static LogCapture all() {
        return new LogCapture("", false);
    }

    /** The messages of the logger named {@code name} at its configured level (e.g. the non-additive audit stream). */
    public static LogCapture named(final String name) {
        return new LogCapture(name, false);
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
        final Configuration config = context.getConfiguration();
        final LoggerConfig target = name.isEmpty() ? config.getRootLogger() : config.getLoggers().get(name);
        if (target != null) {
            target.removeAppender(appender.getName());
            if (created) {
                config.removeLogger(name);
            } else {
                target.setLevel(previousLevel);
            }
        }
        context.updateLoggers();
        appender.stop();
    }
}
