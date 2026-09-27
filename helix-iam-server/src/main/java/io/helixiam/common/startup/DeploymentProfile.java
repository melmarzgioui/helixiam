/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.startup;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.Arrays;

/**
 * Whether the server runs with the {@code dev} Spring profile (local development) or in production mode (every other
 * profile set, the same rule as {@link ProductionReadinessCheck}). Settings that are only safe on a developer machine
 * (plain-text SMTP, an {@code http://} email API URL) are refused unless {@link #isDev()}.
 */
@Component
public class DeploymentProfile {

    private final boolean dev;

    @Autowired
    public DeploymentProfile(final Environment env) {
        this(Arrays.asList(env.getActiveProfiles()).contains("dev"));
    }

    public DeploymentProfile(final boolean dev) {
        this.dev = dev;
    }

    public static DeploymentProfile production() {
        return new DeploymentProfile(false);
    }

    public static DeploymentProfile development() {
        return new DeploymentProfile(true);
    }

    public boolean isDev() {
        return dev;
    }
}
