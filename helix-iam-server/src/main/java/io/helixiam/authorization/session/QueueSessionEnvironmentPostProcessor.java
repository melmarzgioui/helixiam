/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.Map;

/**
 * Helix IAM (Q3): when the HTTP session store is the queue ({@code HELIX_SESSION_STORE=queue}), force
 * {@code spring.session.store-type=none} so Boot's JDBC/Redis session auto-configuration backs off and the
 * queue-backed {@code QueueIndexedSessionRepository} ({@link QueueHttpSessionConfig}) is the only session
 * store. (Boot's {@code StoreType} enum has no "queue" value, so it cannot be set there directly.) Reads the
 * raw {@code HELIX_SESSION_STORE} env var so it is reliable regardless of property-source ordering.
 */
public class QueueSessionEnvironmentPostProcessor implements EnvironmentPostProcessor {

    @Override
    public void postProcessEnvironment(final ConfigurableEnvironment environment, final SpringApplication application) {
        final String store = environment.getProperty("HELIX_SESSION_STORE",
                environment.getProperty("helix.iam.session-store", "jdbc"));
        if ("queue".equalsIgnoreCase(store)) {
            environment.getPropertySources().addFirst(new MapPropertySource("helix-queue-session",
                    Map.of("spring.session.store-type", "none", "helix.iam.session-store", "queue")));
        }
    }
}
