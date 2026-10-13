/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Kubernetes service links: in a namespace with a Service named {@code redis}, every pod gets
 * {@code REDIS_PORT=tcp://<cluster-ip>:<port>}, the same variable the server reads as the Redis port
 * ({@code spring.data.redis.port=${REDIS_PORT:6379}}). Unless something sets it to a plain number first (the Helm chart
 * does, and turns service links off), binding would fail at start-up, also when Redis is not used. This takes the port
 * from that form; a plain value is left as it is.
 */
public class RedisServiceLinkEnvironmentPostProcessor implements EnvironmentPostProcessor {

    static final String REDIS_PORT = "REDIS_PORT";
    private static final Pattern SERVICE_LINK = Pattern.compile("tcp://.+:(\\d{1,5})");

    @Override
    public void postProcessEnvironment(final ConfigurableEnvironment environment, final SpringApplication application) {
        final String value = environment.getProperty(REDIS_PORT);
        if (value == null) {
            return;
        }
        final Matcher link = SERVICE_LINK.matcher(value.trim());
        if (link.matches()) {
            environment.getPropertySources().addFirst(new MapPropertySource("helix-redis-service-link",
                    Map.of(REDIS_PORT, link.group(1))));
        }
    }
}
