/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.json;

import org.springframework.boot.jackson.autoconfigure.JsonMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring Boot's {@code JsonMapper} (Spring MVC bodies, and every {@code ObjectMapper} the application injects):
 * {@code application.properties} restores Boot 3's Jackson 2 defaults ({@code spring.jackson.use-jackson2-defaults}
 * and the pins next to it); this adds what no property covers, {@link JsonMappers#jackson2Compatible}.
 */
@Configuration(proxyBeanMethods = false)
public class JacksonConfig {

    @Bean
    JsonMapperBuilderCustomizer helixJackson2Compatibility() {
        return JsonMappers::jackson2Compatible;
    }
}
