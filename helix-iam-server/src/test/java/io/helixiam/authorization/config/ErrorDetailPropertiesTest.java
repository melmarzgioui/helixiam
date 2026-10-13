/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.web.ErrorProperties;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.support.PropertiesLoaderUtils;

import java.io.IOException;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Security review H3: error bodies never carry the exception message, binding errors, stack trace or exception class.
 * Spring Boot 4 moved these settings from {@code server.error.include-*} to {@code spring.web.error.include-*} and
 * ignores the old keys, so this binds the shipped {@code application.properties} the way Boot does.
 */
class ErrorDetailPropertiesTest {

    @Test
    void theShippedConfiguration_pinsErrorDetailClosed_underTheKeysBootReads() throws IOException {
        final Properties properties = PropertiesLoaderUtils.loadProperties(new ClassPathResource("application.properties"));

        final ErrorProperties error = new Binder(new MapConfigurationPropertySource(properties))
                .bind("spring.web.error", ErrorProperties.class).orElseThrow(() -> new AssertionError("not bound"));

        assertThat(error.getIncludeMessage()).isEqualTo(ErrorProperties.IncludeAttribute.NEVER);
        assertThat(error.getIncludeBindingErrors()).isEqualTo(ErrorProperties.IncludeAttribute.NEVER);
        assertThat(error.getIncludeStacktrace()).isEqualTo(ErrorProperties.IncludeAttribute.NEVER);
        assertThat(error.isIncludeException()).isFalse();
        assertThat(properties.stringPropertyNames()).as("keys Spring Boot 4 ignores")
                .noneMatch(key -> key.startsWith("server.error."));
    }
}
