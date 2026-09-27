/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The global (server-wide) email default, used when the realm in context has no enabled {@code EMAIL} provider, or
 * when there is no realm (prefix {@code helix.notification.email}).
 * <ul>
 *   <li>{@code driver}: {@code smtp} (default; {@code helix.notification.smtp.*}), {@code cloudflare}
 *       ({@code helix.notification.cloudflare.*}) or {@code log};</li>
 *   <li>{@code from-address} / {@code from-name}: the sender; default {@code helix.notification.smtp.from-address} /
 *       {@code from-name}.</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "helix.notification.email")
public class EmailProperties {

    private String driver = "smtp";
    private String fromAddress;
    private String fromName;

    public String getDriver() {
        return driver;
    }

    public void setDriver(final String driver) {
        this.driver = driver;
    }

    public String getFromAddress() {
        return fromAddress;
    }

    public void setFromAddress(final String fromAddress) {
        this.fromAddress = fromAddress;
    }

    public String getFromName() {
        return fromName;
    }

    public void setFromName(final String fromName) {
        this.fromName = fromName;
    }
}
