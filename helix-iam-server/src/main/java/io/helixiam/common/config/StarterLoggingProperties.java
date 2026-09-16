/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.logging.LogLevel;

/**
 * Vendored from io.helixiam.subscriber.starter.config.StarterLoggingProperties.
 * Deviation: dropped {@code amqpBridge}/{@code amqpFederate} fields (there is no message
 * broker in HelixIAM) and renamed the config prefix from {@code mfnr.subscriber.starter.logging}
 * to {@code helixiam.logging}. See VENDOR-MAP.md.
 */
@EnableConfigurationProperties(StarterLoggingProperties.class)
@ConfigurationProperties(prefix = "helixiam.logging")
public record StarterLoggingProperties(LogLevel cacheOrchestrator,
                                        LogLevel subscriberEngine,
                                        LogLevel databases,
                                        LogLevel events,
                                        LogLevel notifications,
                                        LogLevel opensearch,
                                        LogLevel packageLogging) {
}
